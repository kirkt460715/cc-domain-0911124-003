import hashlib
from tests.support import Case, column, recipe, context, policy
from rights_graph.catalog import assets, recipes, tabular
from rights_graph.catalog.records import typed_value, normalize_row
from rights_graph.planner import plans
from rights_graph.planner.preview import evaluate_operator
from rights_graph.primitives import canonical


class PreviewTests(Case):
    def setup_preview(self, rows=None):
        self.source()
        self.derived()
        self.app.preview.data.import_rows('batch', 'source', 1, rows or [{'text': 'alpha'}, {'text': 'beta'}])
        plan, artifact = self.build()
        preview = self.app.preview.run(plan['plan_id'], {'source': 'batch'})
        return plan, artifact, preview

    def test_copy_rows_and_provenance(self):
        plan, artifact, preview = self.setup_preview()
        self.assertEqual(preview['payload']['rows'], [{'text': 'alpha'}, {'text': 'beta'}])
        self.assertEqual(preview['payload']['row_lineage'][0], [{'batch_id': 'batch', 'row_index': 0}])
        self.assertEqual(preview['payload']['alignment'], 'positional_equal_length')
        again = self.app.preview.run(plan['plan_id'], {'source': 'batch'})
        self.assertEqual(preview['preview_id'], again['preview_id'])
        exported = self.app.preview.export(preview['preview_id'], artifact)
        self.assertEqual(exported['data']['sha256'], preview['sha256'])
        self.assertEqual(exported['authorization']['payload']['asset_id'], 'derived')
        self.assertEqual(len(self.app.preview.data.listing()), 1)

    def test_bound_version_and_binding_shape(self):
        plan, artifact, preview = self.setup_preview()
        self.fails('preview_bindings', self.app.preview.run, plan['plan_id'], {})
        self.fails('preview_bindings', self.app.preview.run, plan['plan_id'], {'source': 'batch', 'extra': 'batch'})
        self.fails('preview_limit', self.app.preview.run, plan['plan_id'], {'source': 'batch'}, limit=1)
        self.source('other')
        self.app.preview.data.import_rows('wrong', 'other', 1, [{'text': 'a'}])
        self.fails('preview_version', self.app.preview.run, plan['plan_id'], {'source': 'wrong'})
        self.assertTrue(self.app.preview.get(preview['preview_id'])['freshness']['fresh'])
        self.assertEqual(self.app.preview.data.get('batch')['row_count'], 2)

    def test_source_batch_is_immutable(self):
        self.source()
        data = self.app.preview.data
        original = data.import_rows('batch', 'source', 1, [{'text': 'one'}])
        repeated = data.import_rows('batch', 'source', 1, [{'text': 'one'}])
        self.assertTrue(repeated['duplicate'])
        self.assertEqual(original['digest'], repeated['digest'])
        self.fails('data_batch_conflict', data.import_rows, 'batch', 'source', 1, [{'text': 'two'}])
        self.assertEqual(data.rows('batch')[0]['payload'], {'text': 'one'})
        self.assertTrue(data.verify('batch')['ok'])
        self.assertEqual(data.verify('batch')['rows'], 1)
        self.assertEqual(len(data.listing('source')), 1)

    def test_corrupt_row_and_sequence_detected(self):
        plan, artifact, preview = self.setup_preview()
        data = self.app.preview.data
        self.store.execute("UPDATE data_rows SET payload='{}' WHERE batch_id='batch' AND row_index=0")
        self.fails('data_row_corrupt', data.verify, 'batch')
        self.fails('data_row_corrupt', self.app.preview.run, plan['plan_id'], {'source': 'batch'})
        self.store.execute("DELETE FROM data_rows WHERE batch_id='batch' AND row_index=0")
        self.fails('data_row_order', data.verify, 'batch')
        self.assertEqual(data.get('batch')['row_count'], 2)
        self.assertEqual(data.rows('batch')[0]['row_index'], 1)
        self.assertEqual(self.app.preview.get(preview['preview_id'])['sha256'], preview['sha256'])

    def test_preview_export_rechecks_dependencies(self):
        plan, artifact, preview = self.setup_preview()
        assets.revise(self.store, 'source', 1, [column()], 'Updated source')
        self.assertFalse(self.app.preview.get(preview['preview_id'])['freshness']['fresh'])
        self.fails('preview_stale', self.app.preview.export, preview['preview_id'], artifact)
        self.fails('stale_plan', self.app.preview.run, plan['plan_id'], {'source': 'batch'})
        self.assertEqual(self.app.preview.get(preview['preview_id'])['payload']['rows'][0]['text'], 'alpha')
        self.assertEqual(self.app.preview.data.get('batch')['asset_version'], 1)
        self.assertEqual(assets.get(self.store, 'source')['head'], 2)
        self.assertTrue(self.app.preview.data.verify('batch')['ok'])

    def test_hash_and_redaction_operators(self):
        self.source()
        self.derived(definition=recipe(operator='hash'))
        self.app.preview.data.import_rows('batch', 'source', 1, [{'text': 'secret'}])
        plan, artifact = self.build()
        preview = self.app.preview.run(plan['plan_id'], {'source': 'batch'})
        self.assertEqual(preview['payload']['rows'][0]['text'], hashlib.sha256(canonical('secret').encode()).hexdigest())
        self.assertEqual(preview['payload']['policy']['obligations'], ['attribution'])
        self.assertEqual(evaluate_operator({'operator': 'redact'}, ['secret']), None)
        self.assertEqual(evaluate_operator({'operator': 'hash'}, [None]), None)
        self.assertEqual(evaluate_operator({'operator': 'concat'}, ['a', None]), None)
        self.assertEqual(evaluate_operator({'operator': 'constant', 'constant': 5}, []), 5)

    def test_numeric_aggregation_and_nulls(self):
        self.source(columns=[column('a', 'integer'), column('b', 'integer')])
        definition = {'inputs': [{'asset_id': 'source', 'alias': 'input'}], 'columns': [{'output': 'total', 'operator': 'aggregate', 'sources': [{'input': 'input', 'column': 'a'}, {'input': 'input', 'column': 'b'}]}], 'description': 'Row-wise sum'}
        self.derived(columns=[column('total', 'integer')], definition=definition)
        self.app.preview.data.import_rows('numbers', 'source', 1, [{'a': 2, 'b': 3}, {'a': -2, 'b': 2}])
        plan, artifact = self.build()
        preview = self.app.preview.run(plan['plan_id'], {'source': 'numbers'})
        self.assertEqual(preview['payload']['rows'], [{'total': 5}, {'total': 0}])
        self.assertEqual(evaluate_operator({'operator': 'aggregate'}, ['0.1', '0.2']), '0.3')
        self.assertIsNone(evaluate_operator({'operator': 'aggregate'}, [None, 1]))
        self.fails('preview_aggregate', evaluate_operator, {'operator': 'aggregate'}, [True, 1])
        self.fails('preview_aggregate', evaluate_operator, {'operator': 'aggregate'}, ['bad', 1])

    def test_alignment_does_not_cross_join(self):
        self.source('left')
        self.source('right')
        definition = {'inputs': [{'asset_id': 'left', 'alias': 'l'}, {'asset_id': 'right', 'alias': 'r'}], 'columns': [{'output': 'text', 'operator': 'concat', 'sources': [{'input': 'l', 'column': 'text'}, {'input': 'r', 'column': 'text'}]}], 'description': 'Positionally paired strings'}
        self.derived(definition=definition)
        self.app.preview.data.import_rows('l', 'left', 1, [{'text': 'a'}])
        self.app.preview.data.import_rows('r', 'right', 1, [{'text': 'b'}, {'text': 'c'}])
        plan, artifact = self.build()
        self.fails('preview_alignment', self.app.preview.run, plan['plan_id'], {'left': 'l', 'right': 'r'})
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM previews'), 0)
        self.app.preview.data.import_rows('r2', 'right', 1, [{'text': 'b'}])
        preview = self.app.preview.run(plan['plan_id'], {'left': 'l', 'right': 'r2'})
        self.assertEqual(preview['payload']['rows'], [{'text': 'ab'}])
        self.assertEqual(len(preview['payload']['row_lineage'][0]), 2)

    def test_types_do_not_coerce_booleans(self):
        self.fails('row_integer', typed_value, True, column('n', 'integer'))
        self.fails('row_boolean', typed_value, 1, column('b', 'boolean'))
        self.fails('row_decimal', typed_value, True, column('d', 'decimal'))
        self.fails('row_decimal', typed_value, 'NaN', column('d', 'decimal'))
        self.fails('row_decimal', typed_value, 'Infinity', column('d', 'decimal'))
        self.fails('null_denied', typed_value, None, column())
        self.assertEqual(typed_value('001.2300', column('d', 'decimal')), '1.23')
        self.assertEqual(typed_value('YQ==', column('b', 'bytes')), 'YQ==')
        self.fails('row_bytes', typed_value, '***', column('b', 'bytes'))
        self.assertIsNone(typed_value(None, column(nullable=True)))

    def test_rows_require_schema_but_fill_nullable_fields(self):
        columns = [column(), column('optional', nullable=True)]
        row = normalize_row({'text': 'value'}, columns)
        self.assertEqual(row, {'text': 'value', 'optional': None})
        self.fails('row_missing_column', normalize_row, {}, columns)
        self.fails('row_unknown_columns', normalize_row, {'text': 'a', 'extra': 1}, columns)
        self.fails('row_object', normalize_row, [], columns)
        self.source(columns=columns)
        self.app.preview.data.import_rows('empty', 'source', 1, [])
        self.assertEqual(self.app.preview.data.get('empty')['row_count'], 0)
        self.assertTrue(self.app.preview.data.verify('empty')['ok'])

    def test_csv_and_jsonlines_roundtrip(self):
        self.source()
        self.derived()
        data = self.app.preview.data
        tabular.import_csv(data, 'batch', 'source', 1, 'text\n"a,b"\n"line\nbreak"\n')
        plan, artifact = self.build()
        preview = self.app.preview.run(plan['plan_id'], {'source': 'batch'})
        exported = tabular.export_csv(self.app.preview, preview['preview_id'], artifact)
        self.assertEqual(exported['row_count'], 2)
        self.assertIn('"a,b"', exported['csv'])
        self.assertIn('"line\nbreak"', exported['csv'])
        lines = tabular.export_jsonlines(self.app.preview, preview['preview_id'], artifact)
        imported = tabular.import_jsonlines(data, 'again', 'source', 1, lines['jsonlines'])
        self.assertEqual(imported['digest'], data.get('batch')['digest'])
        self.assertEqual(len(lines['jsonlines'].splitlines()), 2)

    def test_csv_rejects_width_header_and_noncanonical_integer(self):
        self.source(columns=[column('n', 'integer')])
        data = self.app.preview.data
        self.fails('csv_header', tabular.import_csv, data, 'bad', 'source', 1, 'n,n\n1,2\n')
        self.fails('csv_width', tabular.import_csv, data, 'bad', 'source', 1, 'n\n1,2\n')
        self.fails('csv_integer', tabular.import_csv, data, 'bad', 'source', 1, 'n\n01\n')
        self.fails('csv_integer', tabular.import_csv, data, 'bad', 'source', 1, 'n\n 1\n')
        self.fails('jsonlines_blank', tabular.import_jsonlines, data, 'bad', 'source', 1, '\n')
        self.fails('jsonlines_object', tabular.import_jsonlines, data, 'bad', 'source', 1, '[]\n')
        self.assertEqual(data.listing(), [])
        self.assertEqual(tabular.import_csv(data, 'good', 'source', 1, 'n\n-1\n')['row_count'], 1)
