from rights_graph.catalog import assets, recipes, schema
from rights_graph.policy import grants, algebra
from rights_graph.planner import topology
from rights_graph.primitives import GraphError, checksum


def lint(store, request):
    request = algebra.context(request)
    issues = []
    asset_rows = assets.listing(store)
    graph = topology.adjacency(store)
    for asset in asset_rows:
        asset_id = asset['asset_id']
        if asset['state'] == 'retired':
            active_consumers = [node for node in topology.descendants(graph, asset_id) if assets.get(store, node)['state'] == 'active']
            if active_consumers:
                issues.append({'severity': 'error', 'code': 'retired_upstream', 'asset_id': asset_id, 'consumers': active_consumers})
            continue
        if asset['kind'] == 'source':
            available = grants.for_asset(store, asset_id)
            covered = set()
            for grant in available:
                decision = algebra.evaluate(grant['policy'], request)
                if decision['allowed']:
                    covered.update(grant['policy']['columns'])
                else:
                    issues.append({'severity': 'info', 'code': 'grant_inapplicable', 'asset_id': asset_id, 'grant_id': grant['grant_id'], 'reasons': decision['reasons']})
                missing = set(grant['policy']['columns']) - set(schema.by_name(asset['schema']))
                if missing:
                    issues.append({'severity': 'warning', 'code': 'grant_columns_removed', 'asset_id': asset_id, 'grant_id': grant['grant_id'], 'columns': sorted(missing)})
            uncovered = set(schema.by_name(asset['schema'])) - covered
            if uncovered:
                issues.append({'severity': 'warning', 'code': 'uncovered_columns', 'asset_id': asset_id, 'columns': sorted(uncovered)})
        else:
            try:
                recipe = recipes.for_output(store, asset_id)
                definition = recipes.normalize(store, asset_id, recipe['definition'])
            except GraphError as exc:
                issues.append({'severity': 'error', 'code': 'recipe_invalid', 'asset_id': asset_id, 'failure': exc.json()})
                continue
            used_aliases = {ref['input'] for column in definition['columns'] for ref in column['sources']}
            unused = sorted({entry['alias'] for entry in definition['inputs']} - used_aliases)
            if unused:
                issues.append({'severity': 'warning', 'code': 'unused_inputs', 'asset_id': asset_id, 'aliases': unused})
            for column in definition['columns']:
                if column['operator'] == 'constant':
                    from rights_graph.catalog.records import typed_value
                    try:
                        typed_value(column['constant'], schema.by_name(asset['schema'])[column['output']])
                    except GraphError as exc:
                        issues.append({'severity': 'error', 'code': 'constant_type', 'asset_id': asset_id, 'column': column['output'], 'failure': exc.json()})
                if column['operator'] == 'redact' and not schema.by_name(asset['schema'])[column['output']]['nullable']:
                    issues.append({'severity': 'error', 'code': 'redaction_nullability', 'asset_id': asset_id, 'column': column['output']})
            from rights_graph.planner.lineage import compile_graph
            try:
                compile_graph(store, asset_id, request)
            except GraphError as exc:
                issues.append({'severity': 'warning', 'code': 'unbuildable_context', 'asset_id': asset_id, 'failure': exc.json()})
    counts = {severity: sum(issue['severity'] == severity for issue in issues) for severity in ('error', 'warning', 'info')}
    return {'ok': counts['error'] == 0, 'context': request, 'issues': issues, 'counts': counts, 'sha256': checksum(issues)}


def column_graph(store, target):
    visited = set()
    nodes = {}
    edges = []
    def visit(asset_id):
        if asset_id in visited:
            return
        visited.add(asset_id)
        asset = assets.get(store, asset_id)
        for column in asset['schema']:
            identity = asset_id + '.' + column['name']
            nodes[identity] = {'identity': identity, 'asset_id': asset_id, 'column': column['name'], 'type': column['type'], 'classification': column['classification']}
        if asset['kind'] == 'source':
            return
        recipe = recipes.for_output(store, asset_id)
        aliases = {entry['alias']: entry['asset_id'] for entry in recipe['definition']['inputs']}
        for parent in sorted(set(aliases.values())):
            visit(parent)
        for column in recipe['definition']['columns']:
            output = asset_id + '.' + column['output']
            for ref in column['sources']:
                edges.append({'from': aliases[ref['input']] + '.' + ref['column'], 'to': output, 'operator': column['operator'], 'recipe_id': recipe['recipe_id']})
    visit(target)
    edges.sort(key=lambda edge: (edge['from'], edge['to'], edge['operator']))
    return {'target': target, 'nodes': [nodes[key] for key in sorted(nodes)], 'edges': edges}


def consumers_of_column(store, asset_id, column):
    asset = assets.get(store, asset_id)
    if column not in schema.by_name(asset['schema']):
        from rights_graph.primitives import reject
        reject('unknown_column', 'Source column does not exist')
    graph = topology.adjacency(store)
    targets = topology.descendants(graph, asset_id)
    result = []
    source = asset_id + '.' + column
    for target in targets:
        columns = column_graph(store, target)
        reachable = {source}
        while True:
            additions = {edge['to'] for edge in columns['edges'] if edge['from'] in reachable}
            next_reachable = reachable | additions
            if next_reachable == reachable:
                break
            reachable = next_reachable
        affected = sorted(node['column'] for node in columns['nodes'] if node['asset_id'] == target and node['identity'] in reachable)
        if affected:
            result.append({'asset_id': target, 'columns': affected})
    return {'asset_id': asset_id, 'column': column, 'consumers': result}
