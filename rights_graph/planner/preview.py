import hashlib
import json
from decimal import Decimal, localcontext
from rights_graph.primitives import canonical, checksum, count, fields, name, reject
from rights_graph.catalog import assets, recipes
from rights_graph.catalog.records import DataCatalog, typed_value
from rights_graph.planner import plans, artifacts
from rights_graph.journal import audit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS previews(
 preview_id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,bindings TEXT NOT NULL,payload TEXT NOT NULL,
 digest TEXT NOT NULL,created_at TEXT NOT NULL);
'''


def evaluate_operator(rule, values):
    operator = rule['operator']
    if operator == 'constant':
        return rule['constant']
    if operator == 'copy':
        return values[0]
    if operator == 'redact':
        return None
    if operator == 'hash':
        return hashlib.sha256(canonical(values[0]).encode()).hexdigest() if values[0] is not None else None
    if operator == 'concat':
        if any(value is None for value in values):
            return None
        if not all(isinstance(value, str) for value in values):
            reject('preview_concat', 'Concatenation requires string inputs')
        return ''.join(values)
    if operator == 'aggregate':
        if any(value is None for value in values):
            return None
        total = Decimal(0)
        for value in values:
            if isinstance(value, bool):
                reject('preview_aggregate', 'Boolean cannot be aggregated')
            try:
                with localcontext() as arithmetic:
                    arithmetic.prec = 80
                    total += Decimal(str(value))
            except Exception as exc:
                from rights_graph.primitives import GraphError
                raise GraphError('preview_aggregate', 'Aggregate sources must be numeric') from exc
        if not total.is_finite():
            reject('preview_aggregate', 'Aggregate sources must be finite')
        return format(total, 'f') if total else '0'
    reject('preview_operator', 'Unsupported preview operator')


class PreviewEngine:
    def __init__(self, store):
        self.store = store
        self.data = DataCatalog(store)
        if store.depth:
            reject('transaction_scope', 'Initialize preview engine outside transaction')
        store.db.executescript(SCHEMA)

    def run(self, plan_id, bindings, *, limit=10000):
        count(limit, 'limit', 1, 100000)
        if not isinstance(bindings, dict):
            reject('preview_bindings', 'Bindings must map source asset names to batches')
        with self.store.atomic():
            plan = plans.get(self.store, plan_id)
            plans.require_fresh(self.store, plan_id)
            source_ids = {step['asset_id'] for step in plan['payload']['steps'] if step['kind'] == 'source'}
            if set(bindings) != source_ids:
                reject('preview_bindings', 'Bindings must cover precisely the source assets', expected=sorted(source_ids), supplied=sorted(bindings))
            values = {}
            lineage = {}
            for step in plan['payload']['steps']:
                key = (step['asset_id'], step['version'])
                if step['kind'] == 'source':
                    batch_id = bindings[step['asset_id']]
                    batch = self.data.get(batch_id)
                    if batch['asset_id'] != key[0] or batch['asset_version'] != key[1]:
                        reject('preview_version', 'Bound batch does not match planned source version', asset_id=key[0])
                    self.data.verify(batch_id)
                    if batch['row_count'] > limit:
                        reject('preview_limit', 'Source batch exceeds preview row limit')
                    rows = self.data.rows(batch_id, limit=limit)
                    values[key] = [{column: row['payload'][column] for column in step['columns']} for row in rows]
                    lineage[key] = [{'batch_id': batch_id, 'row_index': row['row_index']} for row in rows]
                    continue
                recipe = recipes.get(self.store, step['recipe_id'])
                aliases = {}
                used_aliases = {ref['input'] for rule in recipe['definition']['columns'] if rule['output'] in step['columns'] for ref in rule['sources']}
                for input_spec in recipe['definition']['inputs']:
                    if input_spec['alias'] not in used_aliases:
                        continue
                    source = assets.get(self.store, input_spec['asset_id'], input_spec['version'])
                    parent_key = (source['asset_id'], source['version'])
                    if parent_key in values:
                        aliases[input_spec['alias']] = parent_key
                sizes = {len(values[parent]) for parent in aliases.values()}
                if len(sizes) != 1:
                    reject('preview_alignment', 'Positional preview requires equal row counts for every used input')
                size = next(iter(sizes))
                indexed = {column['name']: column for column in step['schema']}
                rules = {column['output']: column for column in recipe['definition']['columns']}
                output = []
                provenance = []
                for row_index in range(size):
                    row = {}
                    roots = []
                    for column in step['columns']:
                        rule = rules[column]
                        arguments = [values[aliases[reference['input']]][row_index][reference['column']] for reference in rule['sources']]
                        value = evaluate_operator(rule, arguments)
                        if rule['operator'] == 'aggregate' and indexed[column]['type'] == 'integer' and value is not None:
                            parsed = Decimal(value)
                            if parsed != parsed.to_integral_value():
                                reject('preview_integer', 'Aggregate result is not integral')
                            value = int(parsed)
                        row[column] = typed_value(value, indexed[column])
                    for parent in aliases.values():
                        origin = lineage[parent][row_index]
                        roots.extend(origin if isinstance(origin, list) else [origin])
                    dedup = {canonical(origin): origin for origin in roots}
                    output.append(row)
                    provenance.append([dedup[key] for key in sorted(dedup)])
                values[key] = output
                lineage[key] = provenance
            target = plan['payload']['steps'][-1]
            key = (target['asset_id'], target['version'])
            payload = {'plan_id': plan_id, 'target': target['asset_id'], 'rows': values[key], 'row_lineage': lineage[key], 'context': plan['context'], 'policy': target['policy'], 'alignment': 'positional_equal_length'}
            sha = checksum(payload)
            preview_id = 'preview-' + checksum({'plan_id': plan_id, 'bindings': bindings, 'digest': sha})
            self.store.execute('INSERT OR IGNORE INTO previews(preview_id,plan_id,bindings,payload,digest,created_at) VALUES(?,?,?,?,?,?)', (preview_id, plan_id, canonical(bindings), canonical(payload), sha, self.store.clock()))
            audit.append(self.store, 'preview.created', {'preview_id': preview_id, 'plan_id': plan_id, 'rows': len(payload['rows'])})
            return {'preview_id': preview_id, 'payload': payload, 'sha256': sha}

    def get(self, preview_id):
        row = self.store.one('SELECT * FROM previews WHERE preview_id=?', (preview_id,))
        if row is None:
            reject('unknown_preview', 'Preview does not exist')
        payload = json.loads(row['payload'])
        if checksum(payload) != row['digest']:
            reject('preview_corrupt', 'Preview checksum mismatch')
        return {'preview_id': preview_id, 'payload': payload, 'sha256': row['digest'], 'freshness': plans.freshness(self.store, row['plan_id'])}

    def export(self, preview_id, artifact_id):
        with self.store.atomic():
            preview = self.get(preview_id)
            if not preview['freshness']['fresh']:
                reject('preview_stale', 'Preview dependencies changed')
            artifact = artifacts.get(self.store, artifact_id)
            from rights_graph.planner.builds import get
            build = get(self.store, artifact['build_id'])
            if build['plan_id'] != preview['payload']['plan_id'] or artifact['asset_id'] != preview['payload']['target']:
                reject('preview_artifact', 'Artifact does not authorize this preview target')
            attestation = artifacts.export(self.store, artifact_id)
            return {'data': {key: preview[key] for key in ('preview_id', 'payload', 'sha256')}, 'authorization': attestation}
