from collections import deque
from rights_graph.primitives import name, reject


def adjacency(store, replacement=None):
    result = {row['asset_id']: [] for row in store.all('SELECT asset_id FROM assets ORDER BY asset_id')}
    rows = store.all('SELECT r.output_asset,d.input_asset FROM recipes r JOIN dependencies d ON d.recipe_id=r.recipe_id ORDER BY r.output_asset,d.alias')
    for row in rows:
        result[row['output_asset']].append(row['input_asset'])
    if replacement:
        output, inputs = replacement
        result[output] = sorted(set(inputs))
    return {key: sorted(set(values)) for key, values in result.items()}


def ordered(graph, targets=None):
    chosen = sorted(graph) if targets is None else sorted(set(targets))
    visiting = set()
    complete = set()
    result = []
    path = []
    def visit(node):
        if node in complete:
            return
        if node in visiting:
            start = path.index(node)
            reject('graph_cycle', 'Dependency graph contains a cycle', path=path[start:] + [node])
        if node not in graph:
            reject('graph_missing', 'Graph references unknown asset', asset_id=node)
        visiting.add(node)
        path.append(node)
        for dependency in sorted(graph[node]):
            visit(dependency)
        path.pop()
        visiting.remove(node)
        complete.add(node)
        result.append(node)
    for target in chosen:
        visit(target)
    return result


def ancestors(graph, target):
    if target not in graph:
        reject('graph_missing', 'Unknown graph target')
    return ordered(graph, [target])[:-1]


def descendants(graph, source):
    if source not in graph:
        reject('graph_missing', 'Unknown graph source')
    reverse = {node: [] for node in graph}
    for target, dependencies in graph.items():
        for dependency in dependencies:
            reverse.setdefault(dependency, []).append(target)
    seen = set()
    queue = deque(sorted(reverse[source]))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        queue.extend(sorted(reverse[current]))
    return [node for node in ordered(graph) if node in seen]


def levels(graph, target):
    result = {}
    for node in ordered(graph, [target]):
        result[node] = 0 if not graph[node] else 1 + max(result[parent] for parent in graph[node])
    return result


def paths(graph, source, target, limit=1000):
    if limit < 1 or limit > 10000:
        reject('path_limit', 'Path limit outside accepted range')
    ordered(graph)
    result = []
    def walk(node, path):
        if len(result) >= limit:
            return
        if node == source:
            result.append(list(reversed(path + [node])))
            return
        for parent in sorted(graph.get(node, [])):
            walk(parent, path + [node])
    walk(target, [])
    return {'paths': result, 'limit_reached': len(result) == limit}


def summary(store):
    graph = adjacency(store)
    order = ordered(graph)
    degrees = {node: len(parents) for node, parents in graph.items()}
    used = {parent for parents in graph.values() for parent in parents}
    return {
        'nodes': len(graph),
        'edges': sum(degrees.values()),
        'order': order,
        'roots': sorted(node for node, degree in degrees.items() if not degree),
        'sinks': sorted(set(graph) - used),
        'dependencies': graph,
    }
