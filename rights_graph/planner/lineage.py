from rights_graph.primitives import checksum, name, reject, symbols
from rights_graph.catalog import assets, recipes, schema
from rights_graph.policy import algebra, grants


def compile_graph(store, target, request, selected_columns=None, grant_overrides=None):
    request = algebra.context(request)
    grant_overrides = {} if grant_overrides is None else grant_overrides
    if not isinstance(grant_overrides, dict):
        reject('grant_overrides', 'Grant overrides must be object')
    root = assets.get(store, target)
    selected = symbols(selected_columns, 'selected_columns') if selected_columns is not None else [column['name'] for column in root['schema']]
    needed = {}
    definitions = {}
    active = set()
    order = []
    depths = {}
    pinned = {}
    def gather(asset_id, version, columns, depth, fixed):
        asset = assets.get(store, asset_id, version)
        key = (asset_id, asset['version'])
        indexed = schema.by_name(asset['schema'])
        missing = set(columns) - set(indexed)
        if missing:
            reject('lineage_column', 'Selected column is absent', asset_id=asset_id, columns=sorted(missing))
        if asset['state'] != 'active':
            reject('lineage_retired', 'Selected asset is retired', asset_id=asset_id)
        if key in active:
            reject('graph_cycle', 'Cycle encountered while compiling lineage')
        depths[key] = max(depths.get(key, 0), depth)
        pinned[key] = pinned.get(key, True) and fixed
        if key in needed:
            extra = set(columns) - needed[key]
            if not extra:
                return
            needed[key].update(extra)
        else:
            needed[key] = set(columns)
        definitions[key] = {'asset': asset}
        if asset['kind'] == 'derived':
            recipe = recipes.for_output(store, asset_id)
            normalized = recipes.normalize(store, asset_id, recipe['definition'])
            definitions[key]['recipe'] = recipe
            rules = {row['output']: row for row in normalized['columns']}
            aliases = {row['alias']: row for row in normalized['inputs']}
            used = {}
            for column in needed[key]:
                for reference in rules[column]['sources']:
                    used.setdefault(reference['input'], set()).add(reference['column'])
            if not used:
                reject('lineage_no_source', 'Selected derived columns have no source authorization')
            active.add(key)
            for alias in sorted(used):
                input_spec = aliases[alias]
                input_asset = assets.get(store, input_spec['asset_id'], input_spec['version'])
                if input_spec['version'] is not None and input_asset['kind'] == 'derived':
                    reject('derived_pin', 'Only source versions may be pinned')
                gather(input_spec['asset_id'], input_spec['version'], used[alias], depth + 1, input_spec['version'] is not None)
            active.remove(key)
        if key not in order:
            order.append(key)
    gather(target, root['version'], selected, 0, False)
    from rights_graph.planner.topology import ordered
    key_graph = {}
    for key, definition in definitions.items():
        dependencies = set()
        if definition['asset']['kind'] == 'derived':
            recipe = definition['recipe']['definition']
            used_aliases = {ref['input'] for column in recipe['columns'] if column['output'] in needed[key] for ref in column['sources']}
            for spec in recipe['inputs']:
                if spec['alias'] in used_aliases:
                    source = assets.get(store, spec['asset_id'], spec['version'])
                    dependencies.add((source['asset_id'], source['version']))
        key_graph[key] = sorted(dependencies)
    order = ordered(key_graph, [(target, root['version'])])
    depths = {key: 0 for key in order}
    for key in reversed(order):
        for parent in key_graph[key]:
            depths[parent] = max(depths[parent], depths[key] + 1)
    leaves = {}
    for key in order:
        asset = definitions[key]['asset']
        if asset['kind'] != 'source':
            continue
        candidates = grants.for_asset(store, key[0])
        override = grant_overrides.get(key[0])
        if override:
            candidates = [grant for grant in candidates if grant['grant_id'] == override]
        eligible = []
        rejected = []
        for grant in candidates:
            missing = sorted(needed[key] - set(grant['policy']['columns']))
            decision = algebra.evaluate(grant['policy'], request, depth=depths[key])
            reasons = list(decision['reasons'])
            if missing:
                reasons.append({'code': 'columns_denied', 'columns': missing})
            if depths[key] and 'transform' not in grant['policy']['rights']:
                reasons.append({'code': 'transform_denied'})
            if reasons:
                rejected.append({'grant_id': grant['grant_id'], 'reasons': reasons})
            else:
                eligible.append(grant)
        if not eligible:
            reject('authorization_denied', 'No single active grant covers required source columns and context', asset_id=key[0], columns=sorted(needed[key]), candidates=rejected)
        selected_grant = min(eligible, key=lambda grant: (len(grant['policy']['columns']), grant['grant_id']))
        leaves[key] = selected_grant
    computed = {}
    steps = []
    for key in order:
        asset = definitions[key]['asset']
        indexed = schema.by_name(asset['schema'])
        lineage = {}
        column_policies = {}
        if asset['kind'] == 'source':
            grant = leaves[key]
            for column in sorted(needed[key]):
                lineage[column] = [{
                    'asset_id': key[0], 'version': key[1], 'column': column,
                    'grant_id': grant['grant_id'], 'grant_revision': grant['revision'],
                    'depth': 0, 'path': [f'{key[0]}.{column}'],
                }]
                column_policies[column] = algebra.intersect([grant['policy']])
        else:
            recipe = definitions[key]['recipe']
            aliases = {row['alias']: row for row in recipe['definition']['inputs']}
            rules = {row['output']: row for row in recipe['definition']['columns']}
            for column in sorted(needed[key]):
                references = []
                policies = []
                for reference in rules[column]['sources']:
                    input_spec = aliases[reference['input']]
                    source = assets.get(store, input_spec['asset_id'], input_spec['version'])
                    parent = computed[(source['asset_id'], source['version'])]
                    for leaf in parent['lineage'][reference['column']]:
                        references.append({**leaf, 'depth': leaf['depth'] + 1, 'path': leaf['path'] + [f'{key[0]}.{column}']})
                    policies.append(parent['column_policies'][reference['column']])
                if not policies:
                    for input_spec in recipe['definition']['inputs']:
                        source = assets.get(store, input_spec['asset_id'], input_spec['version'])
                        parent = computed.get((source['asset_id'], source['version']))
                        if parent:
                            policies.append(parent['policy'])
                lineage[column] = sorted(references, key=lambda leaf: (leaf['asset_id'], leaf['column'], leaf['path']))
                column_policies[column] = algebra.intersect(policies)
        combined = algebra.intersect(column_policies.values())
        classification = schema.maximum_classification([indexed[column] for column in needed[key]])
        if schema.CLASSIFICATION[classification] > schema.CLASSIFICATION[request['maximum_classification']]:
            reject('classification_denied', 'Selected data exceeds classification ceiling', asset_id=key[0], classification=classification)
        if not combined['usable']:
            reject('policy_intersection_empty', 'Combined source authorization is empty', asset_id=key[0])
        record = {
            'asset_id': key[0], 'version': key[1], 'kind': asset['kind'],
            'pinned': pinned[key], 'content_hash': asset['content_hash'],
            'columns': sorted(needed[key]), 'schema': [indexed[column] for column in sorted(needed[key])],
            'lineage': lineage, 'column_policies': column_policies, 'policy': combined,
            'classification': classification,
            'recipe_id': definitions[key].get('recipe', {}).get('recipe_id'),
            'recipe_revision': definitions[key].get('recipe', {}).get('revision'),
            'recipe_digest': definitions[key].get('recipe', {}).get('digest'),
        }
        record['signature'] = checksum(record)
        computed[key] = record
        steps.append(record)
    unused = sorted(set(grant_overrides) - {key[0] for key in leaves})
    if unused:
        reject('unused_grant_override', 'Grant overrides reference unused source assets', assets=unused)
    return {'target': target, 'context': request, 'selected_columns': selected, 'steps': steps, 'result': computed[(target, root['version'])]}


def trace_column(compiled, column):
    name(column, 'column')
    result = compiled['result']
    if column not in result['lineage']:
        reject('unknown_output_column', 'Column is not in compiled result')
    return {'column': column, 'lineage': result['lineage'][column], 'policy': result['column_policies'][column]}
