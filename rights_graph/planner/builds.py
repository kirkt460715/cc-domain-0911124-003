import datetime as dt
import json
from rights_graph.primitives import canonical, checksum, count, label, name, reject, timestamp
from rights_graph.planner import plans
from rights_graph.journal import audit


def get(store, build_id):
    row = store.one('SELECT * FROM builds WHERE build_id=?', (build_id,))
    if row is None:
        reject('unknown_build', 'Build does not exist')
    for key in ('result', 'error'):
        row[key] = json.loads(row[key]) if row[key] else None
    return row


def create(store, build_id, plan_id):
    name(build_id, 'build_id')
    with store.atomic():
        plan = plans.get(store, plan_id)
        existing = store.one('SELECT plan_id FROM builds WHERE build_id=?', (build_id,))
        if existing:
            if existing['plan_id'] != plan_id:
                reject('build_conflict', 'Build ID refers to another plan')
            return get(store, build_id)
        plans.require_fresh(store, plan_id)
        now = store.clock()
        store.execute("INSERT INTO builds(build_id,plan_id,state,cursor,revision,created_at,updated_at) VALUES(?,?,'queued',0,1,?,?)", (build_id, plan_id, now, now))
        for index, step in enumerate(plan['payload']['steps']):
            store.execute("INSERT INTO build_steps(build_id,step_index,asset_id,state) VALUES(?,?,?,'pending')", (build_id, index, step['asset_id']))
        audit.append(store, 'build.created', {'build_id': build_id, 'plan_id': plan_id})
        return get(store, build_id)


def expiration(store, ttl):
    count(ttl, 'ttl', 1, 3600)
    now = dt.datetime.fromisoformat(store.clock().replace('Z', '+00:00'))
    return (now + dt.timedelta(seconds=ttl)).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def claim(store, build_id, owner, ttl=30):
    name(owner, 'owner')
    with store.atomic():
        build = get(store, build_id)
        if build['state'] not in {'queued', 'running'}:
            reject('build_state', 'Build cannot be claimed in current state')
        if build['state'] == 'running' and build['expires_at'] > store.clock():
            reject('build_busy', 'Build has an active worker')
        generation = (build['lease_generation'] or 0) + 1
        end = expiration(store, ttl)
        store.execute("UPDATE builds SET state='running',owner=?,lease_generation=?,expires_at=?,revision=revision+1,updated_at=? WHERE build_id=?", (owner, generation, end, store.clock(), build_id))
        audit.append(store, 'build.claimed', {'build_id': build_id, 'owner': owner, 'generation': generation})
        return {'build_id': build_id, 'owner': owner, 'generation': generation, 'expires_at': end}


def assert_claim(store, build_id, token):
    if not isinstance(token, dict):
        reject('build_token', 'Build token must be object')
    build = get(store, build_id)
    if build['state'] != 'running':
        reject('build_state', 'Build is not running')
    if token.get('build_id') != build_id or token.get('owner') != build['owner'] or token.get('generation') != build['lease_generation']:
        reject('build_fenced', 'Build token belongs to an earlier worker')
    if build['expires_at'] <= store.clock():
        reject('build_expired', 'Build worker lease has expired')
    return build


def heartbeat(store, build_id, token, ttl=30):
    with store.atomic():
        assert_claim(store, build_id, token)
        end = expiration(store, ttl)
        store.execute('UPDATE builds SET expires_at=?,updated_at=? WHERE build_id=?', (end, store.clock(), build_id))
        return {**token, 'expires_at': end}


def run_step(store, build_id, token):
    with store.atomic():
        build = assert_claim(store, build_id, token)
        plans.require_fresh(store, build['plan_id'])
        plan = plans.get(store, build['plan_id'])
        cursor = build['cursor']
        steps = plan['payload']['steps']
        if cursor >= len(steps):
            return {'finished': True, 'cursor': cursor, 'steps': len(steps)}
        step = steps[cursor]
        if checksum({key: value for key, value in step.items() if key != 'signature'}) != step['signature']:
            reject('step_corrupt', 'Planned step signature is invalid')
        artifact_id = 'artifact-' + checksum({'build_id': build_id, 'step': cursor, 'signature': step['signature']})
        evidence = {
            'artifact_id': artifact_id,
            'asset_id': step['asset_id'],
            'asset_version': step['version'],
            'signature': step['signature'],
            'columns': step['columns'],
            'policy': step['policy'],
            'lineage': step['lineage'],
            'context': plan['context'],
            'manifest_type': 'authorization_lineage',
        }
        store.execute("UPDATE build_steps SET state='verified',payload=?,digest=? WHERE build_id=? AND step_index=? AND state='pending'", (canonical(evidence), checksum(evidence), build_id, cursor))
        store.execute('UPDATE builds SET cursor=cursor+1,revision=revision+1,updated_at=? WHERE build_id=?', (store.clock(), build_id))
        audit.append(store, 'build.step_verified', {'build_id': build_id, 'step': cursor, 'asset_id': step['asset_id'], 'digest': checksum(evidence)})
        return {'finished': cursor + 1 == len(steps), 'cursor': cursor + 1, 'steps': len(steps), 'evidence': evidence}


def finalize(store, build_id, token):
    with store.atomic():
        build = assert_claim(store, build_id, token)
        plans.require_fresh(store, build['plan_id'])
        plan = plans.get(store, build['plan_id'])
        steps = store.all('SELECT * FROM build_steps WHERE build_id=? ORDER BY step_index', (build_id,))
        if build['cursor'] != len(steps) or any(row['state'] != 'verified' for row in steps):
            reject('build_incomplete', 'Every build step must be verified before finalization')
        artifacts = []
        for row in steps:
            evidence = json.loads(row['payload'])
            if checksum(evidence) != row['digest']:
                reject('build_corrupt', 'Verified step digest changed')
            store.execute(
                "INSERT INTO artifacts(artifact_id,asset_id,build_id,signature,policy,lineage,status,created_at) VALUES(?,?,?,?,?,?,'valid',?)",
                (evidence['artifact_id'], evidence['asset_id'], build_id, evidence['signature'], canonical(evidence['policy']), canonical(evidence['lineage']), store.clock()),
            )
            dependencies = set()
            for leaves in evidence['lineage'].values():
                for leaf in leaves:
                    dependencies.add((leaf['asset_id'], leaf['version'], leaf['grant_id'], leaf['grant_revision']))
            for source, version, grant_id, revision in sorted(dependencies):
                store.execute('INSERT INTO artifact_inputs(artifact_id,source_asset,source_version,grant_id,grant_revision) VALUES(?,?,?,?,?)', (evidence['artifact_id'], source, version, grant_id, revision))
            artifacts.append(evidence['artifact_id'])
        result = {'artifacts': artifacts, 'target_artifact': artifacts[-1], 'target': plan['target']}
        store.execute("UPDATE builds SET state='complete',result=?,revision=revision+1,updated_at=?,expires_at=NULL WHERE build_id=?", (canonical(result), store.clock(), build_id))
        audit.append(store, 'build.completed', {'build_id': build_id, **result})
        return get(store, build_id)


def execute(store, build_id, owner='local-worker', ttl=300):
    build = get(store, build_id)
    if build['state'] == 'complete':
        return build
    token = claim(store, build_id, owner, ttl)
    result = run_step(store, build_id, token)
    while not result['finished']:
        token = heartbeat(store, build_id, token, ttl)
        result = run_step(store, build_id, token)
    return finalize(store, build_id, token)


def cancel(store, build_id, expected_revision, reason):
    reason = label(reason, 'reason')
    with store.atomic():
        build = get(store, build_id)
        if build['revision'] != expected_revision:
            reject('stale_build', 'Build revision changed')
        if build['state'] in {'complete', 'cancelled'}:
            reject('build_terminal', 'Terminal build cannot be cancelled')
        store.execute("UPDATE builds SET state='cancelled',error=?,revision=revision+1,updated_at=?,expires_at=NULL WHERE build_id=?", (canonical({'code': 'cancelled', 'reason': reason}), store.clock(), build_id))
        audit.append(store, 'build.cancelled', {'build_id': build_id, 'reason': reason})
        return get(store, build_id)


def steps(store, build_id):
    get(store, build_id)
    rows = store.all('SELECT * FROM build_steps WHERE build_id=? ORDER BY step_index', (build_id,))
    for row in rows:
        row['payload'] = json.loads(row['payload']) if row['payload'] else None
        row['error'] = json.loads(row['error']) if row['error'] else None
    return rows


def listing(store, state=None):
    clause = ' WHERE state=?' if state else ''
    params = [state] if state else []
    return [get(store, row['build_id']) for row in store.all(f'SELECT build_id FROM builds{clause} ORDER BY created_at,build_id', params)]
