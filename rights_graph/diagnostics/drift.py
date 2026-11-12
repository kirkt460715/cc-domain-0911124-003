"""Authorization-bounded distribution drift analysis.

A drift analysis fixes both data batches, the requested fields, the subject
key and the comparison scope at creation time.  Only columns that an active
grant authorizes *for the supplied context* on both sides are ever read, and
only rows carrying a non-null subject key enter the comparison.  Unauthorized
data is projected out before any statistic is computed; it is never used to
build a distribution that is later masked.

Stored diagnostics contain aggregate summaries only (no row-level values).
Every read or export re-evaluates the grants, asset state and batch digests,
so revocation or source failure blocks access without rewriting the frozen
analysis.  Re-running with new batches always creates a separate analysis; an
old analysis is never silently updated.
"""
import hashlib
import json
import random

from rights_graph.primitives import GraphError, canonical, checksum, count, fields, name, reject
from rights_graph.catalog import assets
from rights_graph.catalog.records import DataCatalog
from rights_graph.policy import algebra, grants
from rights_graph.journal import audit
from rights_graph.diagnostics import stats

SCHEMA = '''
CREATE TABLE IF NOT EXISTS drift_analyses(
 analysis_id TEXT PRIMARY KEY,scope TEXT NOT NULL,payload TEXT NOT NULL,
 digest TEXT NOT NULL,created_at TEXT NOT NULL);
'''

NUMERIC_TYPES = {'integer', 'decimal', 'timestamp'}
CATEGORICAL_TYPES = {'string', 'boolean'}
UNSUPPORTED_TYPES = {'bytes'}
DEFAULT_PERMUTATIONS = 100
DEFAULT_MARGINAL_SUBJECTS = 500
DEFAULT_JOINT_SUBJECTS = 200


class DriftDesk:
    def __init__(self, store):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize drift desk outside transaction')
        store.db.executescript(SCHEMA)
        self.data = DataCatalog(store)

    # ------------------------------------------------------------------ setup
    def analyze(self, analysis_id, request):
        name(analysis_id, 'analysis_id')
        fields(request, {'reference_batch', 'candidate_batch', 'subject_key', 'context'},
               {'columns', 'permutations', 'marginal_subject_limit', 'joint_subject_limit', 'seed'})
        context = algebra.context(request['context'])
        subject_key = name(request['subject_key'], 'subject_key')
        permutations = count(request.get('permutations', DEFAULT_PERMUTATIONS), 'permutations', 1, 1000)
        marginal_limit = count(request.get('marginal_subject_limit', DEFAULT_MARGINAL_SUBJECTS),
                               'marginal_subject_limit', 2, 2000)
        joint_limit = count(request.get('joint_subject_limit', DEFAULT_JOINT_SUBJECTS),
                            'joint_subject_limit', 2, 1000)
        seed_text = request.get('seed')
        if seed_text is not None and not isinstance(seed_text, str):
            reject('drift_seed', 'Seed must be text')
        with self.store.atomic():
            existing = self.store.one('SELECT analysis_id FROM drift_analyses WHERE analysis_id=?', (analysis_id,))
            if existing:
                reject('drift_exists', 'Analysis identifier already exists; versioned data needs a new analysis')
            scope = self._resolve_scope(request, context, subject_key)
            payload = self._compute(scope, context, permutations, marginal_limit, joint_limit, seed_text)
            payload['analysis_id'] = analysis_id
            digest = checksum(payload)
            self.store.execute(
                'INSERT INTO drift_analyses(analysis_id,scope,payload,digest,created_at) VALUES(?,?,?,?,?)',
                (analysis_id, canonical(scope['scope']), canonical(payload), digest, self.store.clock()))
            audit.append(self.store, 'drift.analyzed', {
                'analysis_id': analysis_id,
                'reference_batch': scope['reference']['batch_id'],
                'candidate_batch': scope['candidate']['batch_id'],
                'fields': len(payload['fields']),
                'digest': digest,
            })
            return self.get(analysis_id)

    def _resolve_scope(self, request, context, subject_key):
        reference_batch = self.data.get(request['reference_batch'])
        candidate_batch = self.data.get(request['candidate_batch'])
        if reference_batch['batch_id'] == candidate_batch['batch_id']:
            reject('drift_batches', 'Reference and candidate must be different batches')
        ref_asset = assets.get(self.store, reference_batch['asset_id'], reference_batch['asset_version'])
        cand_asset = assets.get(self.store, candidate_batch['asset_id'], candidate_batch['asset_version'])
        if ref_asset['asset_id'] != cand_asset['asset_id']:
            reject('drift_asset', 'Both batches must belong to the same source asset')
        if ref_asset['kind'] != 'source' or cand_asset['kind'] != 'source':
            reject('drift_asset', 'Drift analysis runs on source asset batches')
        ref_schema = {column['name']: column for column in ref_asset['schema']}
        cand_schema = {column['name']: column for column in cand_asset['schema']}
        if subject_key not in ref_schema or subject_key not in cand_schema:
            reject('drift_subject', 'Subject key must exist in both schemas', subject_key=subject_key)
        if subject_key in UNSUPPORTED_TYPES or ref_schema[subject_key]['type'] in UNSUPPORTED_TYPES:
            reject('drift_subject', 'Bytes column cannot be a subject key')
        # Authorization first: establish what each side may expose in this context.
        ref_auth = self._authorized_columns(ref_asset, context)
        cand_auth = self._authorized_columns(cand_asset, context)
        if subject_key not in ref_auth['columns'] or subject_key not in cand_auth['columns']:
            reject('authorization_denied', 'Subject key is not authorized on both sides', subject_key=subject_key)
        requested = request.get('columns')
        if requested is None:
            requested = sorted((set(ref_schema) & set(cand_schema)) - {subject_key})
        else:
            requested = sorted(set(requested))
            if not requested:
                reject('drift_columns', 'At least one comparison field is required')
            if subject_key in requested:
                reject('drift_subject', 'Subject key cannot also be a compared field')
        effective, exclusions = [], []
        for column in requested:
            reason = self._exclusion(column, ref_schema, cand_schema, ref_auth, cand_auth)
            if reason:
                exclusions.append({'column': column, 'reason': reason})
            else:
                effective.append(column)
        if not effective:
            reject('drift_no_effective_fields',
                   'No field is authorized and comparable on both sides',
                   excluded_columns=exclusions)
        scope = {
            'scope': {
                'asset_id': ref_asset['asset_id'],
                'reference': self._batch_scope(reference_batch, ref_asset, ref_auth, context),
                'candidate': self._batch_scope(candidate_batch, cand_asset, cand_auth, context),
                'subject_key': subject_key,
                'requested_columns': requested,
                'effective_columns': effective,
                'excluded_columns': exclusions,
                'context': context,
            },
            'reference': {'batch_id': reference_batch['batch_id'], 'asset': ref_asset, 'authorized': ref_auth},
            'candidate': {'batch_id': candidate_batch['batch_id'], 'asset': cand_asset, 'authorized': cand_auth},
            'ref_schema': ref_schema,
            'cand_schema': cand_schema,
        }
        return scope

    def _authorized_columns(self, asset, context):
        authorized = set()
        grants_used = []
        for grant in grants.for_asset(self.store, asset['asset_id']):
            decision = algebra.evaluate(grant['policy'], context)
            if decision['allowed']:
                authorized.update(grant['policy']['columns'])
                grants_used.append({'grant_id': grant['grant_id'], 'revision': grant['revision']})
        return {'columns': authorized, 'grants': sorted(grants_used, key=lambda item: item['grant_id'])}

    @staticmethod
    def _exclusion(column, ref_schema, cand_schema, ref_auth, cand_auth):
        if column not in ref_schema or column not in cand_schema:
            return 'missing_on_one_side'
        if column not in ref_auth['columns'] or column not in cand_auth['columns']:
            return 'not_authorized'
        ref_type = ref_schema[column]['type']
        cand_type = cand_schema[column]['type']
        if ref_type in UNSUPPORTED_TYPES or cand_type in UNSUPPORTED_TYPES:
            return 'unsupported_type'
        ref_family = 'numeric' if ref_type in NUMERIC_TYPES else 'categorical'
        cand_family = 'numeric' if cand_type in NUMERIC_TYPES else 'categorical'
        if ref_family != cand_family:
            return 'type_family_changed'
        return None

    @staticmethod
    def _batch_scope(batch, asset, authorized, context):
        return {
            'batch_id': batch['batch_id'],
            'asset_version': asset['version'],
            'batch_digest': batch['digest'],
            'row_count': batch['row_count'],
            'content_hash': asset['content_hash'],
            'state': asset['state'],
            'authorized_columns': sorted(authorized['columns']),
            'grants': authorized['grants'],
            'context_at': context['at'],
        }

    # --------------------------------------------------------------- execution
    def _load_rows(self, batch_id, allowed_columns):
        batch = self.data.get(batch_id)
        self.data.verify(batch_id)
        rows = []
        for record in self.data.rows(batch_id, limit=100000):
            # Project before anything else so unauthorized cells never enter memory here.
            rows.append({column: record['payload'][column] for column in allowed_columns})
        if len(rows) != batch['row_count']:
            reject('data_row_order', 'Batch row sequence is incomplete', batch_id=batch_id)
        return rows

    def _compute(self, scope, context, permutations, marginal_limit, joint_limit, seed_text):
        subject_key = scope['scope']['subject_key']
        effective = scope['scope']['effective_columns']
        allowed_ref = sorted(set(effective) | {subject_key})
        allowed_cand = sorted(set(effective) | {subject_key})
        ref_rows = self._load_rows(scope['reference']['batch_id'], allowed_ref)
        cand_rows = self._load_rows(scope['candidate']['batch_id'], allowed_cand)
        seed_material = canonical({
            'reference': scope['reference']['batch_id'], 'candidate': scope['candidate']['batch_id'],
            'subject_key': subject_key, 'columns': effective, 'seed': seed_text,
        })
        seed_integer = int(hashlib.sha256(seed_material.encode()).hexdigest(), 16)
        rng = random.Random(seed_integer)

        coverage = self._coverage(scope, ref_rows, cand_rows, subject_key)
        ref_blocks, cand_blocks = self._subject_blocks(ref_rows, cand_rows, subject_key, rng, marginal_limit)
        boundaries = list(coverage['boundaries'])
        fields_report, raw_pvalues = self._field_reports(
            scope, ref_blocks, cand_blocks, rng, permutations)
        bh = stats.benjamini_hochberg(raw_pvalues)
        for report in fields_report:
            key = report['column']
            report['p_value_adjusted'] = bh['adjusted'].get(key)
            report['significant_bh'] = bh['rejected'].get(key, False)
            boundaries.extend(report.pop('boundaries'))
        joint, joint_boundaries = self._joint_report(
            scope, ref_blocks, cand_blocks, rng, permutations, joint_limit)
        boundaries.extend(joint_boundaries)
        diagnosis = self._diagnosis(coverage, fields_report, joint)
        return {
            'format': 'rights-drift', 'version': 1,
            'scope': scope['scope'],
            'coverage': coverage['report'],
            'fields': fields_report,
            'field_test_family': {'method': 'benjamini_hochberg', **{k: v for k, v in bh.items() if k != 'adjusted' and k != 'rejected'}},
            'joint': joint,
            'diagnosis': diagnosis,
            'boundaries': sorted(set(boundaries)),
            'method': {
                'numeric_distance': 'wasserstein_1',
                'categorical_distance': 'jensen_shannon',
                'joint_distance': 'standardized_energy_distance_reference_scale',
                'permutation': 'subject_block',
                'permutations': permutations,
                'marginal_subject_limit': marginal_limit,
                'joint_subject_limit': joint_limit,
                'quantiles': list(stats.QUANTILES),
                'seed_sha256': hashlib.sha256(seed_material.encode()).hexdigest(),
            },
            'created_context': context,
        }

    def _coverage(self, scope, ref_rows, cand_rows, subject_key):
        ref_total = len(ref_rows)
        cand_total = len(cand_rows)
        ref_null = sum(1 for row in ref_rows if row[subject_key] is None)
        cand_null = sum(1 for row in cand_rows if row[subject_key] is None)
        ref_subjects = {row[subject_key] for row in ref_rows if row[subject_key] is not None}
        cand_subjects = {row[subject_key] for row in cand_rows if row[subject_key] is not None}
        overlap = ref_subjects & cand_subjects
        boundaries = []
        if not ref_subjects or not cand_subjects:
            boundaries.append('no_subjects_one_side')
        if overlap:
            boundaries.append('overlapping_subjects')
        report = {
            'reference': {
                'rows_total': ref_total,
                'rows_with_subject': ref_total - ref_null,
                'rows_missing_subject': ref_null,
                'missing_subject_rate': stats.rounded(ref_null / ref_total) if ref_total else None,
                'distinct_subjects': len(ref_subjects),
            },
            'candidate': {
                'rows_total': cand_total,
                'rows_with_subject': cand_total - cand_null,
                'rows_missing_subject': cand_null,
                'missing_subject_rate': stats.rounded(cand_null / cand_total) if cand_total else None,
                'distinct_subjects': len(cand_subjects),
            },
            'overlapping_subjects': len(overlap),
            'disjoint_subjects': not overlap,
            'compared_fields': len(scope['scope']['effective_columns']),
            'excluded_fields': len(scope['scope']['excluded_columns']),
        }
        return {'report': report, 'boundaries': boundaries}

    @staticmethod
    def _subject_blocks(ref_rows, cand_rows, subject_key, rng, limit):
        def group(rows):
            grouped = {}
            for row in rows:
                key = row[subject_key]
                if key is None:
                    continue
                grouped.setdefault(key, []).append(row)
            blocks = [(key, payload) for key, payload in grouped.items()]
            blocks.sort(key=lambda item: canonical(item[0]))
            if len(blocks) > limit:
                blocks = sorted(rng.sample(blocks, limit), key=lambda item: canonical(item[0]))
            return blocks
        return group(ref_rows), group(cand_rows)

    def _field_reports(self, scope, ref_blocks, cand_blocks, rng, permutations):
        reports = []
        raw_pvalues = {}
        ref_schema = scope['ref_schema']
        cand_schema = scope['cand_schema']
        for column in scope['scope']['effective_columns']:
            ref_type = ref_schema[column]['type']
            family = 'numeric' if ref_type in NUMERIC_TYPES else 'categorical'
            if family == 'numeric':
                report, pvalue = self._numeric_field(column, ref_type, cand_schema[column]['type'],
                                                      ref_blocks, cand_blocks, rng, permutations)
            else:
                report, pvalue = self._categorical_field(
                    column, ref_type, cand_schema[column]['type'],
                    ref_blocks, cand_blocks, rng, permutations)
            reports.append(report)
            if pvalue is not None:
                raw_pvalues[column] = pvalue
        return reports, raw_pvalues

    @staticmethod
    def _flatten(blocks, column):
        return [row[column] for block in blocks for row in block[1]]

    def _numeric_field(self, column, ref_type, cand_type, ref_blocks, cand_blocks, rng, permutations):
        boundaries = []
        if ref_type != cand_type:
            boundaries.append('numeric_type_changed')
        ref_values_raw = self._flatten(ref_blocks, column)
        cand_values_raw = self._flatten(cand_blocks, column)
        ref_n = len(ref_values_raw)
        cand_n = len(cand_values_raw)
        ref_missing = sum(1 for value in ref_values_raw if value is None)
        cand_missing = sum(1 for value in cand_values_raw if value is None)
        ref_present = [stats.as_float(value) for value in ref_values_raw if value is not None]
        cand_present = [stats.as_float(value) for value in cand_values_raw if value is not None]
        report = {
            'column': column, 'family': 'numeric', 'reference_type': ref_type, 'candidate_type': cand_type,
            'sample_size': {'reference_subjects': len(ref_blocks), 'candidate_subjects': len(cand_blocks),
                            'reference_rows': ref_n, 'candidate_rows': cand_n},
            'missing_rate': {
                'reference': stats.rounded(ref_missing / ref_n) if ref_n else None,
                'candidate': stats.rounded(cand_missing / cand_n) if cand_n else None,
            },
            'quantiles': {
                'reference': stats.quantiles(ref_present),
                'candidate': stats.quantiles(cand_present),
            },
            'wasserstein_1': None, 'wasserstein_1_standardized': None,
            'p_value': None, 'permutation_evaluations': 0,
        }
        if not ref_present or not cand_present:
            boundaries.append('all_missing_one_side')
            report['boundaries'] = boundaries
            return report, None
        if len(set(ref_present)) == 1 or len(set(cand_present)) == 1:
            boundaries.append('constant_one_side')
        observed = stats.wasserstein_1(ref_present, cand_present)
        report['wasserstein_1'] = stats.rounded(observed)
        _, ref_std = stats.mean_variance(ref_present)
        if ref_std:
            report['wasserstein_1_standardized'] = stats.rounded(observed / ref_std)

        def statistic(rows_a, rows_b):
            values_a = [stats.as_float(row[column]) for row in rows_a if row[column] is not None]
            values_b = [stats.as_float(row[column]) for row in rows_b if row[column] is not None]
            return stats.wasserstein_1(values_a, values_b)

        pvalue, evaluated = stats.permutation_pvalue(
            observed, ref_blocks, cand_blocks, statistic, rng, permutations)
        report['p_value'] = stats.rounded(pvalue)
        report['permutation_evaluations'] = evaluated
        if pvalue is None:
            boundaries.append('permutation_unavailable')
        report['boundaries'] = boundaries
        return report, pvalue

    def _categorical_field(self, column, ref_type, cand_type, ref_blocks, cand_blocks, rng, permutations):
        boundaries = []
        ref_tokens = [self._token(row[column]) for block in ref_blocks for row in block[1]]
        cand_tokens = [self._token(row[column]) for block in cand_blocks for row in block[1]]
        ref_n = len(ref_tokens)
        cand_n = len(cand_tokens)
        table = stats.category_table(ref_tokens, cand_tokens)
        if table.pop('folded'):
            boundaries.append('high_cardinality_folded')
        observed_pack = stats.jensen_shannon(ref_tokens, cand_tokens)
        report = {
            'column': column, 'family': 'categorical',
            'reference_type': ref_type,
            'candidate_type': cand_type,
            'sample_size': {'reference_subjects': len(ref_blocks), 'candidate_subjects': len(cand_blocks),
                            'reference_rows': ref_n, 'candidate_rows': cand_n},
            'frequency_table': table['categories'],
            'jensen_shannon': observed_pack,
            'p_value': None, 'permutation_evaluations': 0,
        }
        if observed_pack is None:
            boundaries.append('all_missing_one_side')
            report['boundaries'] = boundaries
            return report, None

        def statistic(rows_a, rows_b):
            tokens_a = [self._token(row[column]) for row in rows_a]
            tokens_b = [self._token(row[column]) for row in rows_b]
            pack = stats.jensen_shannon(tokens_a, tokens_b)
            return pack['divergence_nats'] if pack else None

        pvalue, evaluated = stats.permutation_pvalue(
            observed_pack['divergence_nats'], ref_blocks, cand_blocks, statistic, rng, permutations)
        report['p_value'] = stats.rounded(pvalue)
        report['permutation_evaluations'] = evaluated
        if pvalue is None:
            boundaries.append('permutation_unavailable')
        report['boundaries'] = boundaries
        return report, pvalue

    @staticmethod
    def _token(value):
        if value is None:
            return stats.MISSING_CATEGORY
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return str(value)

    def _joint_report(self, scope, ref_blocks, cand_blocks, rng, permutations, joint_limit):
        boundaries = []
        schema = scope['ref_schema']
        numeric_fields = [column for column in scope['scope']['effective_columns']
                          if schema[column]['type'] in NUMERIC_TYPES]
        # Re-sample subject blocks to the (usually smaller) joint budget.
        ref_joint = self._cap_blocks(ref_blocks, joint_limit, rng)
        cand_joint = self._cap_blocks(cand_blocks, joint_limit, rng)
        ref_rows = [row for block in ref_joint for row in block[1]]
        cand_rows = [row for block in cand_joint for row in block[1]]
        scales = {}
        used_fields = []
        for column in numeric_fields:
            values = [stats.as_float(row[column]) for row in ref_rows if row[column] is not None]
            mean, variance = stats.mean_variance(values)
            if mean is None or variance is None or variance == 0.0:
                boundaries.append(f'joint_excluded_constant:{column}')
                continue
            scales[column] = (mean, variance ** 0.5)
            used_fields.append(column)
        if len(used_fields) < 2:
            boundaries.append('joint_insufficient_numeric_fields')
            return {
                'performed': False,
                'reason': 'fewer_than_two_nonconstant_common_numeric_fields',
                'fields_considered': numeric_fields,
                'fields_used': used_fields,
                'sample_size': {'reference_subjects': len(ref_joint), 'candidate_subjects': len(cand_joint)},
            }, boundaries
        ref_vectors, used = stats.standardized_vectors(ref_rows, used_fields, scales)
        cand_vectors, _ = stats.standardized_vectors(cand_rows, used_fields, scales)
        if len(ref_vectors) < 2 or len(cand_vectors) < 2:
            boundaries.append('joint_insufficient_complete_cases')
            return {
                'performed': False,
                'reason': 'not_enough_complete_cases',
                'fields_used': used,
                'reference_complete_cases': len(ref_vectors),
                'candidate_complete_cases': len(cand_vectors),
            }, boundaries
        observed = stats.energy_distance(ref_vectors, cand_vectors)

        def statistic(rows_a, rows_b):
            vectors_a, _ = stats.standardized_vectors(rows_a, used, scales)
            vectors_b, _ = stats.standardized_vectors(rows_b, used, scales)
            return stats.energy_distance(vectors_a, vectors_b)

        pvalue, evaluated = stats.permutation_pvalue(
            observed, ref_joint, cand_joint, statistic, rng, permutations)
        return {
            'performed': True,
            'fields_used': used,
            'standardization': 'reference_mean_and_sample_std',
            'energy_distance': stats.rounded(observed),
            'p_value': stats.rounded(pvalue),
            'permutation_evaluations': evaluated,
            'sample_size': {
                'reference_subjects': len(ref_joint), 'candidate_subjects': len(cand_joint),
                'reference_complete_cases': len(ref_vectors),
                'candidate_complete_cases': len(cand_vectors),
            },
            'note': 'Scales estimated from the reference version only',
        }, boundaries

    @staticmethod
    def _cap_blocks(blocks, limit, rng):
        if len(blocks) <= limit:
            return blocks
        return sorted(rng.sample(blocks, limit), key=lambda item: canonical(item[0]))

    @staticmethod
    def _diagnosis(coverage, field_reports, joint):
        signals = []
        marginal_hits = [report['column'] for report in field_reports if report.get('significant_bh')]
        if coverage['report']['excluded_fields']:
            signals.append({'kind': 'coverage',
                            'detail': 'Some requested fields were excluded; see scope.excluded_columns'})
        if marginal_hits:
            signals.append({'kind': 'marginal', 'columns': marginal_hits,
                            'detail': 'Marginal distribution changed after BH correction'})
        joint_hit = bool(joint.get('performed') and joint.get('p_value') is not None and joint['p_value'] < 0.05)
        if joint_hit:
            signals.append({'kind': 'joint_relationship',
                            'detail': 'Joint energy distance rose while marginals may look unchanged'})
        if not signals:
            headline = 'no_drift_detected'
        elif joint_hit and not marginal_hits:
            headline = 'joint_drift_with_stable_marginals'
        elif marginal_hits and joint_hit:
            headline = 'marginal_and_joint_drift'
        else:
            headline = 'marginal_or_coverage_change'
        return {'headline': headline, 'signals': signals}

    # ---------------------------------------------------------------- storage
    def _row(self, analysis_id):
        row = self.store.one('SELECT * FROM drift_analyses WHERE analysis_id=?', (analysis_id,))
        if row is None:
            reject('unknown_drift_analysis', 'Drift analysis does not exist', analysis_id=analysis_id)
        payload = json.loads(row['payload'])
        if checksum(payload) != row['digest']:
            reject('drift_corrupt', 'Stored drift analysis checksum mismatch')
        return row, payload

    def _revalidate(self, payload):
        """Re-check authorization and source integrity without mutating payload."""
        scope = payload['scope']
        problems = []
        for side in ('reference', 'candidate'):
            spec = scope[side]
            try:
                batch = self.data.get(spec['batch_id'])
                if batch['digest'] != spec['batch_digest']:
                    problems.append({'code': 'batch_changed', 'side': side})
                    continue
                self.data.verify(spec['batch_id'])
                asset = assets.get(self.store, batch['asset_id'], batch['asset_version'])
                if asset['state'] != 'active':
                    problems.append({'code': 'asset_retired', 'side': side})
                if asset['content_hash'] != spec['content_hash'] or asset['version'] != spec['asset_version']:
                    problems.append({'code': 'asset_changed', 'side': side})
                authorized = self._authorized_columns(asset, scope['context'])
                required = set(spec['authorized_columns'])
                if not required <= authorized['columns']:
                    problems.append({'code': 'authorization_narrowed', 'side': side,
                                     'lost_columns': sorted(required - authorized['columns'])})
                current_grants = {(item['grant_id'], item['revision']) for item in authorized['grants']}
                pinned = {(item['grant_id'], item['revision']) for item in spec['grants']}
                if not pinned <= current_grants:
                    problems.append({'code': 'grant_revised_or_revoked', 'side': side})
            except GraphError as exc:  # source failure must block, never silently pass
                problems.append({'code': exc.code, 'side': side})
        return {'valid': not problems, 'problems': problems}

    def get(self, analysis_id):
        name(analysis_id, 'analysis_id')
        with self.store.atomic():
            row, payload = self._row(analysis_id)
            validity = self._revalidate(payload)
            audit.append(self.store, 'drift.read', {
                'analysis_id': analysis_id, 'valid': validity['valid'], 'problems': validity['problems']})
            return {'analysis_id': analysis_id, 'payload': payload, 'sha256': row['digest'],
                    'created_at': row['created_at'], 'validity': validity}

    def export(self, analysis_id):
        name(analysis_id, 'analysis_id')
        with self.store.atomic():
            record = self.get(analysis_id)
            if not record['validity']['valid']:
                reject('drift_export_blocked', 'Authorization or source validity failed; export refused',
                       problems=record['validity']['problems'])
            envelope = {
                'format': 'rights-drift-export', 'version': 1,
                'analysis_id': analysis_id,
                'diagnostic': record['payload'],
                'validity': record['validity'],
                'note': 'Aggregate diagnostics only; no row-level or unauthorized detail',
            }
            digest = checksum(envelope)
            audit.append(self.store, 'drift.exported', {'analysis_id': analysis_id, 'sha256': digest})
            return {'export': envelope, 'sha256': digest, 'created_at': record['created_at']}

    def listing(self):
        rows = self.store.all('SELECT analysis_id,digest,created_at FROM drift_analyses ORDER BY created_at,analysis_id')
        return rows
