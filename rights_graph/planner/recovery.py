import json
from rights_graph.primitives import checksum, name, reject
from rights_graph.planner import plans, builds
from rights_graph.journal import audit


def checkpoint(store, build_id):
    build = builds.get(store, build_id)
    plan = plans.get(store, build['plan_id'])
    steps = builds.steps(store, build_id)
    verified = []
    pending = []
    errors = []
    for index, step in enumerate(steps):
        if step['step_index'] != index:
            errors.append({'code': 'step_sequence', 'index': index})
        if step['state'] == 'verified':
            verified.append(index)
            if step['payload'] is None or checksum(step['payload']) != step['digest']:
                errors.append({'code': 'step_digest', 'index': index})
            elif step['payload']['signature'] != plan['payload']['steps'][index]['signature']:
                errors.append({'code': 'step_signature', 'index': index})
        else:
            pending.append(index)
    if verified != list(range(build['cursor'])):
        errors.append({'code': 'cursor_mismatch', 'cursor': build['cursor'], 'verified': verified})
    if len(steps) != len(plan['payload']['steps']):
        errors.append({'code': 'step_count'})
    freshness = plans.freshness(store, build['plan_id'])
    errors.extend(freshness['problems'])
    busy = build['state'] == 'running' and build['expires_at'] > store.clock()
    return {'build_id': build_id, 'state': build['state'], 'cursor': build['cursor'], 'verified': verified, 'pending': pending, 'problems': errors, 'active_worker': busy, 'resumable': not errors and not busy and build['state'] in {'queued', 'running'}}


def resume(store, build_id, owner='recovery-worker'):
    with store.atomic():
        inspected = checkpoint(store, build_id)
        if not inspected['resumable']:
            reject('recovery_unsafe', 'Build cannot be resumed from this checkpoint', checkpoint=inspected)
        result = builds.execute(store, build_id, owner)
        audit.append(store, 'build.resumed', {'build_id': build_id, 'from_cursor': inspected['cursor'], 'owner': owner})
        return result


def replan(store, old_build_id, new_build_id, *, context=None):
    name(new_build_id, 'new_build_id')
    with store.atomic():
        old = builds.get(store, old_build_id)
        if old['state'] == 'running' and old['expires_at'] > store.clock():
            reject('replan_busy', 'Cannot replace an actively leased build')
        plan = plans.get(store, old['plan_id'])
        request = plan['context'] if context is None else context
        candidate = plans.create(store, plan['target'], request, columns=plan['payload']['steps'][-1]['columns'])
        created = builds.create(store, new_build_id, candidate['plan_id'])
        audit.append(store, 'build.replanned', {'old_build_id': old_build_id, 'new_build_id': new_build_id, 'before': plan['plan_id'], 'after': candidate['plan_id']})
        return {'build': created, 'changes': plans.compare(store, plan['plan_id'], candidate['plan_id'])}


def queue(store):
    result = {'resumable': [], 'busy': [], 'blocked': []}
    for build in builds.listing(store):
        if build['state'] not in {'queued', 'running'}:
            continue
        report = checkpoint(store, build['build_id'])
        if report['active_worker']:
            result['busy'].append(report)
        elif report['resumable']:
            result['resumable'].append(report)
        else:
            result['blocked'].append(report)
    return result


def verify_history(store):
    errors = []
    for row in store.all('SELECT * FROM grant_versions ORDER BY grant_id,revision'):
        snapshot = json.loads(row['snapshot'])
        if snapshot['grant_id'] != row['grant_id'] or snapshot['revision'] != row['revision']:
            errors.append({'code': 'grant_history_identity', 'grant_id': row['grant_id'], 'revision': row['revision']})
    for grant in store.all('SELECT grant_id,revision FROM grants'):
        versions = store.all('SELECT revision FROM grant_versions WHERE grant_id=? ORDER BY revision', (grant['grant_id'],))
        if [row['revision'] for row in versions] != list(range(1, grant['revision'] + 1)):
            errors.append({'code': 'grant_history_gap', 'grant_id': grant['grant_id']})
    for recipe in store.all('SELECT recipe_id,revision FROM recipes'):
        versions = store.all('SELECT * FROM recipe_versions WHERE recipe_id=? ORDER BY revision', (recipe['recipe_id'],))
        if [row['revision'] for row in versions] != list(range(1, recipe['revision'] + 1)):
            errors.append({'code': 'recipe_history_gap', 'recipe_id': recipe['recipe_id']})
        for row in versions:
            if checksum(json.loads(row['definition'])) != row['digest']:
                errors.append({'code': 'recipe_history_digest', 'recipe_id': recipe['recipe_id'], 'revision': row['revision']})
    for asset in store.all('SELECT asset_id,head FROM assets'):
        versions = store.all('SELECT version FROM asset_versions WHERE asset_id=? ORDER BY version', (asset['asset_id'],))
        if [row['version'] for row in versions] != list(range(1, asset['head'] + 1)):
            errors.append({'code': 'asset_history_gap', 'asset_id': asset['asset_id']})
    return {'ok': not errors, 'problems': errors}
