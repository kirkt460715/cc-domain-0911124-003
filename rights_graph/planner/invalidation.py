import json
from rights_graph.primitives import canonical, label
from rights_graph.planner import topology
from rights_graph.journal import audit


def mark(store, artifact_ids, cause, details):
    affected = []
    for artifact_id in sorted(set(artifact_ids)):
        row = store.one('SELECT status FROM artifacts WHERE artifact_id=?', (artifact_id,))
        if row is None or row['status'] != 'valid':
            continue
        store.execute("UPDATE artifacts SET status='invalid',invalid_reason=? WHERE artifact_id=?", (cause, artifact_id))
        store.execute('INSERT INTO invalidations(artifact_id,cause,details,at) VALUES(?,?,?,?)', (artifact_id, cause, canonical(details), store.clock()))
        affected.append(artifact_id)
    return affected


def invalidate_grant(store, grant_id, cause):
    rows = store.all('SELECT DISTINCT artifact_id FROM artifact_inputs WHERE grant_id=? ORDER BY artifact_id', (grant_id,))
    return mark(store, [row['artifact_id'] for row in rows], cause, {'grant_id': grant_id})


def invalidate_asset(store, asset_id, cause, *, only_unpinned=False):
    graph = topology.adjacency(store)
    targets = {asset_id, *topology.descendants(graph, asset_id)}
    if only_unpinned:
        direct = store.all('SELECT r.output_asset FROM dependencies d JOIN recipes r ON r.recipe_id=d.recipe_id WHERE d.input_asset=? AND d.pinned_version IS NULL', (asset_id,))
        targets = {asset_id}
        for row in direct:
            targets.add(row['output_asset'])
            targets.update(topology.descendants(graph, row['output_asset']))
    ids = []
    for target in sorted(targets):
        ids.extend(row['artifact_id'] for row in store.all("SELECT artifact_id FROM artifacts WHERE asset_id=? AND status='valid'", (target,)))
    return mark(store, ids, cause, {'asset_id': asset_id, 'only_unpinned': only_unpinned})


def history(store, artifact_id=None):
    if artifact_id is None:
        rows = store.all('SELECT * FROM invalidations ORDER BY invalidation_id')
    else:
        rows = store.all('SELECT * FROM invalidations WHERE artifact_id=? ORDER BY invalidation_id', (artifact_id,))
    for row in rows:
        row['details'] = json.loads(row['details'])
    return rows


def expired(store, at):
    from rights_graph.primitives import timestamp
    at = timestamp(at)
    affected = []
    with store.atomic():
        for row in store.all("SELECT artifact_id,policy FROM artifacts WHERE status='valid' ORDER BY artifact_id"):
            policy = json.loads(row['policy'])
            if policy['valid_until'] <= at:
                affected.extend(mark(store, [row['artifact_id']], 'authorization_expired', {'at': at}))
        audit.append(store, 'artifacts.expired', {'at': at, 'affected': affected})
    return affected
