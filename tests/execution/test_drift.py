import json
import random

from tests.support import Case, column, context
from rights_graph.catalog import assets
from rights_graph.policy import grants
from rights_graph.primitives import GraphError, checksum

POLICY_COLUMNS = ['subject', 'x', 'y', 'segment', 'secret', 'flag']


def drift_context(**changes):
    value = context(right='read', fulfilled_obligations=[])
    value.update(changes)
    return value


def policy(columns):
    return {
        'purposes': ['research'], 'regions': ['cn'], 'rights': ['read', 'transform'],
        'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z',
        'obligations': [], 'columns': columns, 'max_depth': 10, 'allow_derivatives': True,
    }


def schema():
    return [
        column('subject', 'string', 'internal', True),
        column('x', 'decimal', 'internal', True),
        column('y', 'decimal', 'internal', True),
        column('segment', 'string', 'internal', True),
        column('secret', 'string', 'restricted', True),
        column('flag', 'boolean', 'internal', True),
    ]


def correlated_rows(n, correlation, seed, *, disjoint=False):
    rng = random.Random(seed)
    rows = []
    for index in range(n):
        first = rng.gauss(0, 1)
        second = rng.gauss(0, 1)
        x = first
        y = correlation * first + (1 - correlation * correlation) ** 0.5 * second
        prefix = 'b' if disjoint else 'a'
        rows.append({
            'subject': f'{prefix}-{index:04d}',
            'x': str(round(x, 4)),
            'y': str(round(y, 4)),
            'segment': None if index % 19 == 0 else ('core' if index % 2 else 'edge'),
            'secret': f'classified-{index}',
            'flag': index % 2 == 0,
        })
    return rows


class DriftTests(Case):
    def setUp(self):
        super().setUp()
        assets.create(self.store, 'src', 'source', 'owner', schema(), 'synthetic source')
        grants.create(self.store, 'g-src', 'src', policy(POLICY_COLUMNS))
        self.ref_rows = correlated_rows(160, 0.0, 11)
        self.cand_rows = correlated_rows(160, 0.9, 22)
        self.app.preview.data.import_rows('ref', 'src', 1, self.ref_rows)
        assets.revise(self.store, 'src', 1, schema(), 'partner refresh')
        self.app.preview.data.import_rows('cand', 'src', 2, self.cand_rows)
        self.request = {
            'reference_batch': 'ref', 'candidate_batch': 'cand',
            'subject_key': 'subject', 'context': drift_context(), 'permutations': 40,
        }

    def analyze(self, analysis_id='drift-1', **changes):
        request = {**self.request, **changes}
        return self.app.drift.analyze(analysis_id, request)

    def test_stable_marginals_but_changed_correlation_is_joint_drift(self):
        result = self.analyze()
        payload = result['payload']
        self.assertEqual(payload['diagnosis']['headline'], 'joint_drift_with_stable_marginals')
        self.assertTrue(payload['joint']['performed'])
        self.assertIsNotNone(payload['joint']['p_value'])
        self.assertLess(payload['joint']['p_value'], 0.05)
        # Marginals of x and y must not survive as significant marginal signals.
        by_column = {item['column']: item for item in payload['fields']}
        for name in ('x', 'y'):
            self.assertFalse(by_column[name]['significant_bh'])
            self.assertIsNotNone(by_column[name]['wasserstein_1'])
            self.assertIsNotNone(by_column[name]['p_value_adjusted'])
        self.assertEqual(payload['method']['numeric_distance'], 'wasserstein_1')
        self.assertEqual(payload['method']['categorical_distance'], 'jensen_shannon')

    def test_numeric_report_keeps_effect_size_sample_size_and_quantiles(self):
        result = self.analyze()
        numeric = next(item for item in result['payload']['fields'] if item['column'] == 'x')
        self.assertEqual(numeric['family'], 'numeric')
        self.assertEqual(numeric['sample_size']['reference_rows'], 160)
        self.assertEqual(numeric['sample_size']['candidate_rows'], 160)
        self.assertEqual(numeric['sample_size']['reference_subjects'], 160)
        self.assertIn('0.5', numeric['quantiles']['reference'])
        self.assertIn('0.99', numeric['quantiles']['candidate'])
        self.assertIsNotNone(numeric['missing_rate']['reference'])
        self.assertGreaterEqual(numeric['permutation_evaluations'], 1)

    def test_categorical_report_includes_missing_category_and_frequencies(self):
        result = self.analyze()
        categorical = next(item for item in result['payload']['fields'] if item['column'] == 'segment')
        categories = {row['category']: row for row in categorical['frequency_table']}
        self.assertIn(None, categories)
        missing = categories[None]
        self.assertEqual(missing['reference_count'], sum(1 for row in self.ref_rows if row['segment'] is None))
        self.assertAlmostEqual(missing['reference_frequency'], missing['candidate_frequency'])
        self.assertIsNotNone(categorical['jensen_shannon']['divergence_nats'])
        boolean_field = next(item for item in result['payload']['fields'] if item['column'] == 'flag')
        self.assertEqual(boolean_field['family'], 'categorical')
        labels = {row['category'] for row in boolean_field['frequency_table']}
        self.assertEqual(labels, {'false', 'true'})

    def test_identical_distributions_have_zero_distances(self):
        identical = [dict(row) for row in self.ref_rows]
        self.app.preview.data.import_rows('same', 'src', 2, identical)
        request = {**self.request, 'candidate_batch': 'same', 'permutations': 20}
        payload = self.app.drift.analyze('drift-same', request)['payload']
        for field in payload['fields']:
            if field['family'] == 'numeric':
                self.assertEqual(field['wasserstein_1'], 0.0)
            else:
                self.assertEqual(field['jensen_shannon']['divergence_nats'], 0.0)
        self.assertEqual(payload['joint']['energy_distance'], 0.0)
        self.assertEqual(payload['diagnosis']['headline'], 'no_drift_detected')

    def test_unauthorized_columns_are_excluded_before_statistics(self):
        # Narrow the grant so neither side may read the restricted column.
        grant = grants.get(self.store, 'g-src')
        grants.revise(self.store, 'g-src', grant['revision'],
                      policy(['subject', 'x', 'y', 'segment', 'flag']), 'drop secret')
        result = self.analyze()
        columns = {item['column'] for item in result['payload']['fields']}
        self.assertNotIn('secret', columns)
        # Asking explicitly for an unauthorized field reports it, never computes it.
        explicit = self.analyze('drift-explicit', columns=['x', 'secret'])
        excluded = {item['column']: item['reason']
                    for item in explicit['payload']['scope']['excluded_columns']}
        self.assertEqual(excluded, {'secret': 'not_authorized'})
        self.assertEqual([item['column'] for item in explicit['payload']['fields']], ['x'])
        # No unauthorized value leaks anywhere in the stored diagnostic.
        encoded = json.dumps(explicit['payload'], ensure_ascii=False)
        self.assertNotIn('classified-', encoded)

    def test_denied_context_blocks_the_analysis(self):
        with self.assertRaises(GraphError) as caught:
            self.analyze('drift-denied', context=drift_context(purpose='marketing'))
        self.assertEqual(caught.exception.code, 'authorization_denied')

    def test_subject_overlap_and_disjoint_scopes_are_documented(self):
        overlap = self.analyze()
        self.assertIn('overlapping_subjects', overlap['payload']['boundaries'])
        self.assertFalse(overlap['payload']['coverage']['disjoint_subjects'])
        disjoint_candidate = correlated_rows(160, 0.9, 33, disjoint=True)
        self.app.preview.data.import_rows('cand-disjoint', 'src', 2, disjoint_candidate)
        disjoint = self.analyze('drift-disjoint', candidate_batch='cand-disjoint')
        self.assertTrue(disjoint['payload']['coverage']['disjoint_subjects'])
        self.assertNotIn('overlapping_subjects', disjoint['payload']['boundaries'])

    def test_repeated_subjects_move_as_whole_blocks(self):
        repeated = []
        for row in self.cand_rows[:80]:
            repeated.extend([row, dict(row)])  # same subject key, duplicated rows
        self.app.preview.data.import_rows('cand-repeat', 'src', 2, repeated)
        result = self.analyze('drift-repeat', candidate_batch='cand-repeat', permutations=20)
        coverage = result['payload']['coverage']['candidate']
        self.assertEqual(coverage['rows_total'], 160)
        self.assertEqual(coverage['distinct_subjects'], 80)
        # Sampling never splits a subject: subject counts never exceed distinct count.
        for field in result['payload']['fields']:
            self.assertLessEqual(field['sample_size']['candidate_subjects'], 80)

    def test_missing_subject_rows_are_excluded_from_comparison(self):
        broken = [dict(row, subject=None) for row in self.cand_rows[:10]] + self.cand_rows[10:]
        self.app.preview.data.import_rows('cand-null', 'src', 2, broken)
        result = self.analyze('drift-null', candidate_batch='cand-null')
        side = result['payload']['coverage']['candidate']
        self.assertEqual(side['rows_missing_subject'], 10)
        self.assertEqual(side['rows_with_subject'], 150)
        self.assertAlmostEqual(side['missing_subject_rate'], round(10 / 160, 6))

    def test_revocation_blocks_read_and_export_without_mutating_analysis(self):
        created = self.analyze()
        original_digest = created['sha256']
        grant = grants.get(self.store, 'g-src')
        grants.revoke(self.store, 'g-src', grant['revision'], 'source withdrawal')
        fetched = self.app.dispatch('drift.get', {'analysis_id': 'drift-1'})
        self.assertFalse(fetched['validity']['valid'])
        self.assertTrue(any(problem['side'] == 'reference' for problem in fetched['validity']['problems']))
        self.fails('drift_export_blocked', self.app.dispatch, 'drift.export', {'analysis_id': 'drift-1'})
        # Frozen payload is untouched by the re-validation.
        self.assertEqual(fetched['sha256'], original_digest)

    def test_grant_narrowing_is_caught_on_revalidation(self):
        self.analyze()
        grant = grants.get(self.store, 'g-src')
        grants.revise(self.store, 'g-src', grant['revision'],
                      policy(['subject', 'x', 'y']), 'narrow columns')
        fetched = self.app.dispatch('drift.get', {'analysis_id': 'drift-1'})
        self.assertFalse(fetched['validity']['valid'])
        codes = {problem['code'] for problem in fetched['validity']['problems']}
        self.assertIn('grant_revised_or_revoked', codes)
        self.assertIn('authorization_narrowed', codes)
        self.fails('drift_export_blocked', self.app.dispatch, 'drift.export', {'analysis_id': 'drift-1'})

    def test_corrupt_batch_invalidates_the_saved_diagnostic(self):
        self.analyze()
        self.store.execute("UPDATE data_rows SET payload='{}' WHERE batch_id='ref' AND row_index=0")
        fetched = self.app.dispatch('drift.get', {'analysis_id': 'drift-1'})
        self.assertFalse(fetched['validity']['valid'])
        codes = {problem['code'] for problem in fetched['validity']['problems']}
        self.assertTrue({'data_row_corrupt', 'data_batch_corrupt'} & codes)

    def test_analysis_is_immutable_and_versioned(self):
        self.analyze()
        self.fails('drift_exists', self.app.drift.analyze, 'drift-1', self.request)
        # A new batch requires a brand new analysis; the old one is never refreshed.
        refreshed = correlated_rows(160, -0.8, 44)
        self.app.preview.data.import_rows('cand-2', 'src', 2, refreshed)
        second = self.analyze('drift-2', candidate_batch='cand-2')
        first = self.app.dispatch('drift.get', {'analysis_id': 'drift-1'})
        self.assertNotEqual(first['sha256'], second['sha256'])
        self.assertEqual(first['payload']['scope']['candidate']['batch_id'], 'cand')
        listing = self.app.dispatch('drift.list', {})
        self.assertEqual([row['analysis_id'] for row in listing], ['drift-1', 'drift-2'])

    def test_all_missing_and_constant_fields_are_boundary_conditions(self):
        constant_candidate = [dict(row, x=None, y='3.5') for row in self.cand_rows]
        self.app.preview.data.import_rows('cand-flat', 'src', 2, constant_candidate)
        payload = self.analyze('drift-flat', candidate_batch='cand-flat')['payload']
        by_column = {item['column']: item for item in payload['fields']}
        x_field = by_column['x']
        self.assertIsNone(x_field['wasserstein_1'])
        self.assertIsNone(x_field['p_value'])
        self.assertIn('all_missing_one_side', payload['boundaries'])
        y_field = by_column['y']
        self.assertIsNotNone(y_field['wasserstein_1'])
        self.assertIn('constant_one_side', payload['boundaries'])

    def test_type_family_change_is_reported_without_distance(self):
        new_schema = [dict(col) for col in schema()]
        next(item for item in new_schema if item['name'] == 'y')['type'] = 'string'
        assets.revise(self.store, 'src', 2, new_schema, 'y becomes text', allow_breaking=True)
        text_rows = [dict(row, y=f'v-{index}') for index, row in enumerate(self.cand_rows)]
        self.app.preview.data.import_rows('cand-text', 'src', 3, text_rows)
        payload = self.analyze('drift-type', candidate_batch='cand-text')['payload']
        excluded = {item['column']: item['reason']
                    for item in payload['scope']['excluded_columns']}
        self.assertEqual(excluded['y'], 'type_family_changed')
        self.assertNotIn('y', {item['column'] for item in payload['fields']})

    def test_no_subjects_on_one_side_marks_inference_boundary(self):
        empty_subject = [dict(row, subject=None) for row in self.cand_rows]
        self.app.preview.data.import_rows('cand-empty', 'src', 2, empty_subject)
        payload = self.analyze('drift-empty', candidate_batch='cand-empty')['payload']
        self.assertIn('no_subjects_one_side', payload['boundaries'])
        self.assertEqual(payload['coverage']['candidate']['distinct_subjects'], 0)
        self.assertFalse(payload['joint']['performed'])

    def test_deterministic_output_for_fixed_seed(self):
        first = self.analyze('drift-a', seed='fixed')
        second = self.analyze('drift-b', seed='fixed')
        first_payload = dict(first['payload'])
        second_payload = dict(second['payload'])
        self.assertEqual(first_payload.pop('analysis_id'), 'drift-a')
        self.assertEqual(second_payload.pop('analysis_id'), 'drift-b')
        self.assertEqual(checksum(first_payload), checksum(second_payload))

    def test_bh_family_adjusts_multiple_marginal_tests(self):
        result = self.analyze()
        family = result['payload']['field_test_family']
        self.assertEqual(family['method'], 'benjamini_hochberg')
        # Three effective fields participate in one family.
        self.assertEqual(family['family_size'], len(result['payload']['fields']))

    def test_all_fields_excluded_is_rejected_not_silently_empty(self):
        grant = grants.get(self.store, 'g-src')
        grants.revise(self.store, 'g-src', grant['revision'], policy(['subject']), 'only key remains')
        with self.assertRaises(GraphError) as caught:
            self.analyze('drift-none')
        self.assertEqual(caught.exception.code, 'drift_no_effective_fields')

    def test_bytes_columns_are_unsupported(self):
        new_schema = [dict(col) for col in schema()]
        next(item for item in new_schema if item['name'] == 'segment')['type'] = 'bytes'
        assets.revise(self.store, 'src', 2, new_schema, 'segment becomes bytes', allow_breaking=True)
        encoded_rows = []
        import base64
        for index, row in enumerate(self.cand_rows):
            copied = dict(row)
            copied['segment'] = base64.b64encode(f'v{index}'.encode()).decode()
            encoded_rows.append(copied)
        self.app.preview.data.import_rows('cand-bytes', 'src', 3, encoded_rows)
        payload = self.analyze('drift-bytes', candidate_batch='cand-bytes')['payload']
        excluded = {item['column']: item['reason']
                    for item in payload['scope']['excluded_columns']}
        self.assertEqual(excluded['segment'], 'unsupported_type')
