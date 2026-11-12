import contextlib
import io
import json
import pathlib
import tempfile
from tests.support import Case, column, context, recipe
from rights_graph.cli import main, execute_stream, read_json, write_json
from rights_graph.catalog import importing
from rights_graph.planner import plans


class CliTests(Case):
    def test_stream_preserves_success_and_reports_failures(self):
        self.source()
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'requests.jsonl'
            requests = [{'operation': 'asset.get', 'arguments': {'asset_id': 'source'}}, {'operation': 'asset.get', 'arguments': {'asset_id': 'missing'}}, {'operation': 'system.check', 'arguments': {}}]
            path.write_text(''.join(json.dumps(row) + '\n' for row in requests))
            result = execute_stream(self.app, str(path))
            self.assertEqual(result['failed'], 1)
            self.assertEqual(result['succeeded'], 2)
            self.assertEqual(result['results'][0]['result']['asset_id'], 'source')
            self.assertEqual(result['results'][1]['error']['code'], 'unknown_asset')
            self.assertTrue(result['results'][2]['result']['ok'])
            stopped = execute_stream(self.app, str(path), True)
            self.assertEqual(len(stopped['results']), 2)
            self.assertEqual(stopped['failed'], 1)

    def test_cli_check_and_structured_error_codes(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(['--db', ':memory:', 'check'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['ok'])
        with tempfile.TemporaryDirectory() as folder:
            request = pathlib.Path(folder) / 'input.json'
            request.write_text('{"asset_id":"missing"}')
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                code = main(['--db', ':memory:', 'call', 'asset.get', '--input', str(request)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(error.getvalue())['error']['code'], 'unknown_asset')
            self.assertFalse(json.loads(error.getvalue())['ok'])

    def test_output_file_no_overwrite_and_input_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            output = pathlib.Path(folder) / 'output.json'
            write_json({'hello': 'world'}, str(output))
            self.assertEqual(json.loads(output.read_text()), {'hello': 'world'})
            self.fails('output_exists', write_json, {'hello': 'changed'}, str(output))
            self.assertEqual(read_json(str(output)), {'hello': 'world'})
            self.fails('input_size', read_json, str(output), maximum=1)
            self.assertEqual(output.read_text().count('\n'), 1)
            self.assertIn('world', output.read_text())
            self.assertNotIn('changed', output.read_text())

    def test_concatenation_preserves_declared_argument_order(self):
        self.source(columns=[column('a'), column('z')])
        definition = recipe(source_column='z', operator='concat')
        definition['columns'][0]['sources'].append({'input': 'input', 'column': 'a'})
        self.derived(definition=definition)
        self.app.preview.data.import_rows('batch', 'source', 1, [{'a': 'second', 'z': 'first'}])
        plan, artifact = self.build()
        preview = self.app.preview.run(plan['plan_id'], {'source': 'batch'})
        self.assertEqual(preview['payload']['rows'], [{'text': 'firstsecond'}])
        self.assertEqual(preview['payload']['row_lineage'][0], [{'batch_id': 'batch', 'row_index': 0}])
        self.assertTrue(self.app.preview.export(preview['preview_id'], artifact)['authorization'])
        self.assertEqual(self.app.dispatch('system.check', {})['ok'], True)

    def test_exact_decimal_does_not_round_long_integer_part(self):
        from rights_graph.catalog.records import typed_value
        from rights_graph.planner.preview import evaluate_operator
        spec = column('amount', 'decimal')
        value = '12345678901234567890123456789.12'
        self.assertEqual(typed_value(value, spec), value)
        self.assertEqual(typed_value('-0.000', spec), '0')
        self.assertEqual(typed_value('10.000', spec), '10')
        result = evaluate_operator({'operator': 'aggregate'}, [value, '0.01'])
        self.assertEqual(result, '12345678901234567890123456789.13')
        self.fails('row_decimal', typed_value, '0.0000000000000000001', spec)
        self.fails('preview_aggregate', evaluate_operator, {'operator': 'aggregate'}, ['NaN'])
