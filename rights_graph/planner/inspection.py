import json
from rights_graph.primitives import checksum, reject
from rights_graph.catalog import assets, recipes
from rights_graph.planner import topology, plans, builds, artifacts
from rights_graph.journal import audit


def overview(store):
    kinds = store.all('SELECT kind,COUNT(*) AS count FROM assets GROUP BY kind ORDER BY kind')
    statuses = store.all('SELECT status,COUNT(*) AS count FROM artifacts GROUP BY status ORDER BY status')
    build_states = store.all('SELECT state,COUNT(*) AS count FROM builds GROUP BY state ORDER BY state')
    return {
        'assets': {row['kind']: row['count'] for row in kinds},
        'grants': store.scalar('SELECT COUNT(*) FROM grants'),
        'active_grants': store.scalar("SELECT COUNT(*) FROM grants WHERE state='active'"),
        'recipes': store.scalar('SELECT COUNT(*) FROM recipes'),
        'plans': store.scalar('SELECT COUNT(*) FROM plans'),
        'artifacts': {row['status']: row['count'] for row in statuses},
        'builds': {row['state']: row['count'] for row in build_states},
    }


def check(store):
    problems = []
    with store.atomic():
        database = store.integrity()
        journal = audit.verify(store)
        if not database['ok']:
            problems.append({'code': 'database_integrity', 'details': database})
        if not journal['ok']:
            problems.append({'code': 'audit_integrity', 'details': journal})
        from rights_graph.primitives import GraphError
        try:
            graph = topology.summary(store)
        except GraphError as exc:
            problems.append(exc.json())
            graph = None
        for row in store.all('SELECT * FROM recipes ORDER BY recipe_id'):
            definition = json.loads(row['definition'])
            if checksum(definition) != row['digest']:
                problems.append({'code': 'recipe_digest', 'recipe_id': row['recipe_id']})
            expected = sorted((entry['asset_id'], entry['alias'], entry['version']) for entry in definition['inputs'])
            actual = sorted((entry['input_asset'], entry['alias'], entry['pinned_version']) for entry in store.all('SELECT * FROM dependencies WHERE recipe_id=?', (row['recipe_id'],)))
            if expected != actual:
                problems.append({'code': 'dependency_index', 'recipe_id': row['recipe_id']})
        for row in store.all('SELECT * FROM plans ORDER BY plan_id'):
            if checksum(json.loads(row['payload'])) != row['digest']:
                problems.append({'code': 'plan_digest', 'plan_id': row['plan_id']})
        for row in store.all('SELECT * FROM builds ORDER BY build_id'):
            steps = store.all('SELECT * FROM build_steps WHERE build_id=? ORDER BY step_index', (row['build_id'],))
            verified = [step for step in steps if step['state'] == 'verified']
            if row['cursor'] != len(verified):
                problems.append({'code': 'build_cursor', 'build_id': row['build_id']})
            if any(step['step_index'] != index for index, step in enumerate(steps)):
                problems.append({'code': 'build_step_order', 'build_id': row['build_id']})
            for step in verified:
                if checksum(json.loads(step['payload'])) != step['digest']:
                    problems.append({'code': 'build_step_digest', 'build_id': row['build_id'], 'step': step['step_index']})
            artifact_count = store.scalar('SELECT COUNT(*) FROM artifacts WHERE build_id=?', (row['build_id'],))
            if row['state'] == 'complete' and artifact_count != len(steps):
                problems.append({'code': 'build_artifact_count', 'build_id': row['build_id']})
            if row['state'] != 'complete' and artifact_count:
                problems.append({'code': 'premature_artifact', 'build_id': row['build_id']})
        for row in store.all('SELECT * FROM artifacts ORDER BY artifact_id'):
            lineage = json.loads(row['lineage'])
            expected = sorted({(leaf['asset_id'], leaf['version'], leaf['grant_id'], leaf['grant_revision']) for leaves in lineage.values() for leaf in leaves})
            actual = sorted((item['source_asset'], item['source_version'], item['grant_id'], item['grant_revision']) for item in store.all('SELECT * FROM artifact_inputs WHERE artifact_id=?', (row['artifact_id'],)))
            if expected != actual:
                problems.append({'code': 'artifact_input_index', 'artifact_id': row['artifact_id']})
        return {'ok': not problems, 'problems': problems, 'database': database, 'audit': journal, 'graph': graph}


def explain_asset(store, asset_id):
    asset = assets.get(store, asset_id)
    graph = topology.adjacency(store)
    from rights_graph.policy.grants import for_asset
    return {
        'asset': asset,
        'ancestors': topology.ancestors(graph, asset_id),
        'descendants': topology.descendants(graph, asset_id),
        'grants': for_asset(store, asset_id, active_only=False) if asset['kind'] == 'source' else [],
        'recipe': recipes.for_output(store, asset_id) if asset['kind'] == 'derived' and store.one('SELECT recipe_id FROM recipes WHERE output_asset=?', (asset_id,)) else None,
        'artifacts': artifacts.listing(store, asset_id),
    }


def dependency_change_impact(store, asset_id, candidate_schema):
    from rights_graph.catalog.schema import compatibility, by_name
    asset = assets.get(store, asset_id)
    compatible = compatibility(asset['schema'], candidate_schema)
    available = by_name(candidate_schema)
    direct = []
    for row in store.all('SELECT r.recipe_id,r.output_asset,d.alias,d.pinned_version FROM dependencies d JOIN recipes r ON r.recipe_id=d.recipe_id WHERE d.input_asset=? ORDER BY r.recipe_id,d.alias', (asset_id,)):
        recipe = recipes.get(store, row['recipe_id'])
        required = sorted({reference['column'] for column in recipe['definition']['columns'] for reference in column['sources'] if reference['input'] == row['alias']})
        missing = sorted(set(required) - set(available))
        direct.append({**row, 'required_columns': required, 'missing_columns': missing, 'affected': row['pinned_version'] is None})
    graph = topology.adjacency(store)
    return {'asset_id': asset_id, 'schema_compatibility': compatible, 'direct_consumers': direct, 'transitive_consumers': topology.descendants(graph, asset_id)}


def artifact_proof(store, artifact_id):
    artifact = artifacts.get(store, artifact_id)
    build = builds.get(store, artifact['build_id'])
    plan = plans.get(store, build['plan_id'])
    step = next((step for step in builds.steps(store, build['build_id']) if step['payload'] and step['payload']['artifact_id'] == artifact_id), None)
    if step is None:
        reject('artifact_step_missing', 'Artifact has no verified build step')
    return {'artifact': artifact, 'build': build, 'plan_digest': plan['digest'], 'step': step, 'live_verification': artifacts.verify(store, artifact_id)}
