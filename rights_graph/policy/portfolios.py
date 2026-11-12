from rights_graph.primitives import fields, name, reject, checksum
from rights_graph.policy import algebra, grants
from rights_graph.catalog import assets, schema
from rights_graph.planner.lineage import compile_graph


def assess(store, targets, requests):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 100:
        reject('portfolio_targets', 'Portfolio needs a bounded target list')
    if not isinstance(requests, list) or not 1 <= len(requests) <= 100:
        reject('portfolio_contexts', 'Portfolio needs a bounded context list')
    if len(set(targets)) != len(targets):
        reject('portfolio_duplicate', 'Portfolio target repeats')
    contexts = [algebra.context(request) for request in requests]
    from rights_graph.primitives import GraphError
    results = []
    for target in targets:
        assets.get(store, target)
        for index, request in enumerate(contexts):
            try:
                result = compile_graph(store, target, request)
                roots = sorted({leaf['grant_id'] for leaves in result['result']['lineage'].values() for leaf in leaves})
                results.append({'target': target, 'context_index': index, 'allowed': True, 'grants': roots, 'columns': result['selected_columns'], 'policy': result['result']['policy']})
            except GraphError as exc:
                results.append({'target': target, 'context_index': index, 'allowed': False, 'error': exc.json()})
    coverage = []
    for index, request in enumerate(contexts):
        matching = [row for row in results if row['context_index'] == index]
        coverage.append({'context_index': index, 'allowed': sum(row['allowed'] for row in matching), 'total': len(matching)})
    return {'contexts': contexts, 'results': results, 'coverage': coverage, 'sha256': checksum(results)}


def minimal_columns(store, target, request):
    asset = assets.get(store, target)
    from rights_graph.primitives import GraphError
    authorized = []
    denied = []
    for column in asset['schema']:
        try:
            result = compile_graph(store, target, request, [column['name']])
            authorized.append({'column': column['name'], 'policy': result['result']['policy'], 'sources': result['result']['lineage'][column['name']]})
        except GraphError as exc:
            denied.append({'column': column['name'], 'error': exc.json()})
    combined = None
    combined_failure = None
    if authorized:
        try:
            result = compile_graph(store, target, request, [column['column'] for column in authorized])
            combined = result['result']['policy']
        except GraphError as exc:
            combined_failure = exc.json()
    return {'target': target, 'authorized_individually': authorized, 'denied': denied, 'combined_policy': combined, 'combined_failure': combined_failure, 'union_is_authorized': combined is not None}


def obligation_inventory(store, target):
    from rights_graph.planner import topology
    graph = topology.adjacency(store)
    asset = assets.get(store, target)
    upstream = [target] + topology.ancestors(graph, target)
    inventory = {}
    for asset_id in upstream:
        source = assets.get(store, asset_id)
        if source['kind'] != 'source':
            continue
        for grant in grants.for_asset(store, asset_id):
            for obligation in grant['policy']['obligations']:
                entry = inventory.setdefault(obligation, {'obligation': obligation, 'grants': [], 'assets': set()})
                entry['grants'].append(grant['grant_id'])
                entry['assets'].add(asset_id)
    return {'target': target, 'obligations': [{'obligation': key, 'grants': sorted(inventory[key]['grants']), 'assets': sorted(inventory[key]['assets'])} for key in sorted(inventory)], 'semantics': 'inventory_of_alternatives_not_an_authorization_decision'}


def compare_contexts(store, target, before, after):
    left = minimal_columns(store, target, before)
    right = minimal_columns(store, target, after)
    old = {entry['column'] for entry in left['authorized_individually']}
    new = {entry['column'] for entry in right['authorized_individually']}
    return {
        'target': target,
        'lost_columns': sorted(old - new),
        'gained_columns': sorted(new - old),
        'retained_columns': sorted(old & new),
        'before_union_authorized': left['union_is_authorized'],
        'after_union_authorized': right['union_is_authorized'],
        'before': left,
        'after': right,
    }
