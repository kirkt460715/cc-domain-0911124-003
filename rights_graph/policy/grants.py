import json
from rights_graph.primitives import canonical, count, label, name, reject
from rights_graph.catalog import assets
from rights_graph.policy.algebra import normalize, narrowing
from rights_graph.journal import audit


def get(store, grant_id, revision=None):
    name(grant_id, 'grant_id')
    if revision is not None:
        count(revision, 'revision', 1)
        row = store.one('SELECT snapshot FROM grant_versions WHERE grant_id=? AND revision=?', (grant_id, revision))
        if row is None:
            reject('unknown_grant_revision', 'Grant revision does not exist')
        return json.loads(row['snapshot'])
    row = store.one('SELECT * FROM grants WHERE grant_id=?', (grant_id,))
    if row is None:
        reject('unknown_grant', 'Grant does not exist', grant_id=grant_id)
    row['policy'] = json.loads(row['policy'])
    return row


def remember(store, grant_id):
    row = get(store, grant_id)
    store.execute('INSERT INTO grant_versions(grant_id,revision,snapshot) VALUES(?,?,?)', (grant_id, row['revision'], canonical(row)))
    return row


def create(store, grant_id, asset_id, policy):
    name(grant_id, 'grant_id')
    normalized = normalize(policy)
    with store.atomic():
        asset = assets.get(store, asset_id)
        if asset['kind'] != 'source' or asset['state'] != 'active':
            reject('grant_asset', 'Grants attach to active source assets')
        missing = set(normalized['columns']) - {column['name'] for column in asset['schema']}
        if missing:
            reject('grant_columns', 'Grant references absent source columns', columns=sorted(missing))
        if store.one('SELECT grant_id FROM grants WHERE grant_id=?', (grant_id,)):
            reject('grant_exists', 'Grant already exists')
        now = store.clock()
        store.execute("INSERT INTO grants(grant_id,asset_id,revision,state,policy,created_at,updated_at) VALUES(?,?,1,'active',?,?,?)", (grant_id, asset_id, canonical(normalized), now, now))
        row = remember(store, grant_id)
        audit.append(store, 'grant.created', {'grant_id': grant_id, 'asset_id': asset_id})
        return row


def revise(store, grant_id, expected_revision, policy, reason):
    count(expected_revision, 'expected_revision', 1)
    reason = label(reason, 'reason')
    normalized = normalize(policy)
    with store.atomic():
        previous = get(store, grant_id)
        if previous['revision'] != expected_revision:
            reject('stale_grant', 'Grant revision changed')
        if previous['state'] == 'revoked':
            reject('grant_terminal', 'Revoked grant cannot be revised')
        asset = assets.get(store, previous['asset_id'])
        if set(normalized['columns']) - {column['name'] for column in asset['schema']}:
            reject('grant_columns', 'Grant references absent source columns')
        store.execute('UPDATE grants SET revision=revision+1,policy=?,reason=?,updated_at=? WHERE grant_id=?', (canonical(normalized), reason, store.clock(), grant_id))
        from rights_graph.planner.invalidation import invalidate_grant
        affected = invalidate_grant(store, grant_id, 'grant_revised')
        row = remember(store, grant_id)
        audit.append(store, 'grant.revised', {'grant_id': grant_id, 'revision': row['revision'], 'narrowing': narrowing(previous['policy'], normalized), 'affected': affected})
        return row


def revoke(store, grant_id, expected_revision, reason):
    reason = label(reason, 'reason')
    with store.atomic():
        previous = get(store, grant_id)
        if previous['revision'] != expected_revision:
            reject('stale_grant', 'Grant revision changed')
        if previous['state'] == 'revoked':
            return previous
        store.execute("UPDATE grants SET revision=revision+1,state='revoked',reason=?,updated_at=? WHERE grant_id=?", (reason, store.clock(), grant_id))
        from rights_graph.planner.invalidation import invalidate_grant
        affected = invalidate_grant(store, grant_id, 'grant_revoked')
        row = remember(store, grant_id)
        audit.append(store, 'grant.revoked', {'grant_id': grant_id, 'reason': reason, 'affected': affected})
        return row


def for_asset(store, asset_id, active_only=True):
    assets.get(store, asset_id)
    clause = " AND state='active'" if active_only else ''
    return [get(store, row['grant_id']) for row in store.all(f'SELECT grant_id FROM grants WHERE asset_id=?{clause} ORDER BY grant_id', (asset_id,))]


def history(store, grant_id):
    get(store, grant_id)
    return [json.loads(row['snapshot']) for row in store.all('SELECT snapshot FROM grant_versions WHERE grant_id=? ORDER BY revision', (grant_id,))]
