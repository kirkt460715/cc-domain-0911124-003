import json
from rights_graph.primitives import canonical, checksum, name, reject
from rights_graph.catalog import assets, recipes
from rights_graph.policy import grants
from rights_graph.planner.lineage import compile_graph
from rights_graph.journal import audit


def create(store, target, context, *, columns=None, grant_overrides=None):
    with store.atomic():
        compiled = compile_graph(store, target, context, columns, grant_overrides)
        payload = {key: value for key, value in compiled.items() if key != 'result'}
        sha = checksum(payload)
        plan_id = 'plan-' + sha
        existing = store.one('SELECT plan_id FROM plans WHERE plan_id=?', (plan_id,))
        if existing:
            return get(store, plan_id)
        store.execute("INSERT INTO plans(plan_id,target,context,payload,digest,state,created_at) VALUES(?,?,?,?,?,'planned',?)", (plan_id, target, canonical(compiled['context']), canonical(payload), sha, store.clock()))
        audit.append(store, 'plan.created', {'plan_id': plan_id, 'target': target, 'steps': len(payload['steps'])})
        return get(store, plan_id)


def get(store, plan_id):
    row = store.one('SELECT * FROM plans WHERE plan_id=?', (plan_id,))
    if row is None:
        reject('unknown_plan', 'Build plan does not exist')
    row['context'] = json.loads(row['context'])
    row['payload'] = json.loads(row['payload'])
    if checksum(row['payload']) != row['digest']:
        reject('plan_corrupt', 'Plan content differs from checksum')
    return row


def freshness(store, plan_id):
    plan = get(store, plan_id)
    problems = []
    seen_grants = set()
    for step in plan['payload']['steps']:
        current = assets.get(store, step['asset_id'])
        if current['state'] != 'active':
            problems.append({'code': 'asset_retired', 'asset_id': step['asset_id']})
        if not step['pinned'] and current['head'] != step['version']:
            problems.append({'code': 'asset_head_changed', 'asset_id': step['asset_id'], 'planned': step['version'], 'current': current['head']})
        pinned_version = assets.get(store, step['asset_id'], step['version'])
        if pinned_version['content_hash'] != step['content_hash']:
            problems.append({'code': 'asset_content_changed', 'asset_id': step['asset_id']})
        if step['recipe_id']:
            recipe = recipes.get(store, step['recipe_id'])
            if recipe['revision'] != step['recipe_revision'] or recipe['digest'] != step['recipe_digest']:
                problems.append({'code': 'recipe_changed', 'recipe_id': step['recipe_id']})
        for leaves in step['lineage'].values():
            for leaf in leaves:
                grant_id = leaf['grant_id']
                if grant_id in seen_grants:
                    continue
                seen_grants.add(grant_id)
                current_grant = grants.get(store, grant_id)
                if current_grant['state'] != 'active' or current_grant['revision'] != leaf['grant_revision']:
                    problems.append({'code': 'grant_changed', 'grant_id': grant_id, 'planned': leaf['grant_revision'], 'current': current_grant['revision']})
    return {'fresh': not problems, 'problems': problems, 'plan_id': plan_id}


def require_fresh(store, plan_id):
    result = freshness(store, plan_id)
    if not result['fresh']:
        reject('stale_plan', 'Plan dependencies changed', problems=result['problems'])
    return result


def listing(store, target=None):
    if target is None:
        rows = store.all('SELECT plan_id FROM plans ORDER BY created_at,plan_id')
    else:
        name(target, 'target')
        rows = store.all('SELECT plan_id FROM plans WHERE target=? ORDER BY created_at,plan_id', (target,))
    return [get(store, row['plan_id']) for row in rows]


def compare(store, before, after):
    left = get(store, before)
    right = get(store, after)
    old = {(step['asset_id'], step['version']): step for step in left['payload']['steps']}
    new = {(step['asset_id'], step['version']): step for step in right['payload']['steps']}
    differences = []
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            differences.append({'asset_id': key[0], 'version': key[1], 'before': old.get(key), 'after': new.get(key)})
    return {'before': before, 'after': after, 'differences': differences, 'context_changed': left['context'] != right['context']}
