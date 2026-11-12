import json
from rights_graph.primitives import canonical, checksum, label, reject, timestamp
from rights_graph.policy import algebra, grants
from rights_graph.planner import plans, builds, invalidation
from rights_graph.journal import audit


def get(store, artifact_id):
    row = store.one('SELECT * FROM artifacts WHERE artifact_id=?', (artifact_id,))
    if row is None:
        reject('unknown_artifact', 'Authorization artifact does not exist')
    row['policy'] = json.loads(row['policy'])
    row['lineage'] = json.loads(row['lineage'])
    return row


def verify(store, artifact_id, request=None):
    artifact = get(store, artifact_id)
    build = builds.get(store, artifact['build_id'])
    plan = plans.get(store, build['plan_id'])
    request = plan['context'] if request is None else algebra.context(request)
    failures = []
    if artifact['status'] != 'valid':
        failures.append({'code': 'artifact_invalid', 'reason': artifact['invalid_reason']})
    fresh = plans.freshness(store, build['plan_id'])
    failures.extend(fresh['problems'])
    decision = algebra.evaluate(artifact['policy'], request)
    failures.extend(decision['reasons'])
    seen = set()
    for leaves in artifact['lineage'].values():
        for leaf in leaves:
            key = (leaf['grant_id'], leaf['depth'])
            if key in seen:
                continue
            seen.add(key)
            grant = grants.get(store, leaf['grant_id'])
            if grant['state'] != 'active':
                failures.append({'code': 'grant_revoked', 'grant_id': grant['grant_id']})
            leaf_decision = algebra.evaluate(grant['policy'], request, depth=leaf['depth'])
            for reason in leaf_decision['reasons']:
                failures.append({'grant_id': grant['grant_id'], **reason})
    return {'valid': not failures, 'artifact_id': artifact_id, 'failures': failures, 'context': request}


def export(store, artifact_id, request=None):
    with store.atomic():
        decision = verify(store, artifact_id, request)
        if not decision['valid']:
            reject('artifact_unusable', 'Artifact cannot be exported under requested context', failures=decision['failures'])
        artifact = get(store, artifact_id)
        build = builds.get(store, artifact['build_id'])
        plan = plans.get(store, build['plan_id'])
        matching = [step for step in plan['payload']['steps'] if step['asset_id'] == artifact['asset_id'] and step['signature'] == artifact['signature']]
        if len(matching) != 1:
            reject('artifact_plan', 'Artifact does not match exactly one plan step')
        payload = {
            'format': 'rights-lineage-attestation',
            'version': 1,
            'artifact_id': artifact_id,
            'asset_id': artifact['asset_id'],
            'signature': artifact['signature'],
            'schema': matching[0]['schema'],
            'policy': artifact['policy'],
            'lineage': artifact['lineage'],
            'context': decision['context'],
            'source_inputs': store.all('SELECT source_asset,source_version,grant_id,grant_revision FROM artifact_inputs WHERE artifact_id=? ORDER BY source_asset,source_version,grant_id', (artifact_id,)),
        }
        sha = checksum(payload)
        export_id = 'export-' + sha
        store.execute('INSERT OR IGNORE INTO exports(export_id,artifact_id,digest,payload,created_at) VALUES(?,?,?,?,?)', (export_id, artifact_id, sha, canonical(payload), store.clock()))
        audit.append(store, 'artifact.exported', {'export_id': export_id, 'artifact_id': artifact_id, 'digest': sha})
        return {'export_id': export_id, 'payload': payload, 'sha256': sha}


def verify_export(value):
    from rights_graph.primitives import fields
    fields(value, {'export_id', 'payload', 'sha256'})
    if checksum(value['payload']) != value['sha256'] or value['export_id'] != 'export-' + value['sha256']:
        reject('export_integrity', 'Export digest does not match payload')
    payload = value['payload']
    if payload.get('format') != 'rights-lineage-attestation' or payload.get('version') != 1:
        reject('export_format', 'Unsupported export format')
    decision = algebra.evaluate(payload['policy'], payload['context'])
    return {'integrity': True, 'declared_context_allowed': decision['allowed'], 'reasons': decision['reasons'], 'live_revocation_checked': False}


def listing(store, asset_id=None, status=None):
    conditions = []
    params = []
    if asset_id:
        conditions.append('asset_id=?')
        params.append(asset_id)
    if status:
        if status not in {'valid', 'invalid'}:
            reject('artifact_status', 'Unknown artifact status')
        conditions.append('status=?')
        params.append(status)
    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
    return [get(store, row['artifact_id']) for row in store.all(f'SELECT artifact_id FROM artifacts{where} ORDER BY created_at,artifact_id', params)]


def withdraw(store, artifact_id, reason):
    reason = label(reason, 'reason')
    with store.atomic():
        get(store, artifact_id)
        affected = invalidation.mark(store, [artifact_id], 'operator_withdrawal', {'reason': reason})
        audit.append(store, 'artifact.withdrawn', {'artifact_id': artifact_id, 'reason': reason})
        return {'affected': affected, 'artifact': get(store, artifact_id)}
