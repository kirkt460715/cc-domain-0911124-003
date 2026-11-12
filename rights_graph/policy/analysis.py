import json
from rights_graph.primitives import checksum, count, fields, name, reject, timestamp
from rights_graph.policy import algebra, grants
from rights_graph.catalog import assets, recipes
from rights_graph.planner import topology


def alternatives(store, asset_id, columns, request, depth=0):
    asset = assets.get(store, asset_id)
    available = {column['name'] for column in asset['schema']}
    if set(columns) - available:
        reject('unknown_columns', 'Requested columns are absent')
    request = algebra.context(request)
    rows = []
    for grant in grants.for_asset(store, asset_id, active_only=False):
        decision = algebra.evaluate(grant['policy'], request, depth=depth)
        reasons = list(decision['reasons'])
        missing = sorted(set(columns) - set(grant['policy']['columns']))
        if missing:
            reasons.append({'code': 'columns_denied', 'columns': missing})
        if grant['state'] != 'active':
            reasons.append({'code': 'grant_revoked'})
        rows.append({
            'grant_id': grant['grant_id'],
            'revision': grant['revision'],
            'allowed': not reasons,
            'reasons': reasons,
            'extra_columns': sorted(set(grant['policy']['columns']) - set(columns)),
            'expires_at': grant['policy']['valid_until'],
        })
    rows.sort(key=lambda row: (not row['allowed'], len(row['extra_columns']), row['grant_id']))
    return {'asset_id': asset_id, 'columns': sorted(columns), 'candidates': rows, 'selected': next((row['grant_id'] for row in rows if row['allowed']), None)}


def coverage_matrix(store, asset_id, requests):
    asset = assets.get(store, asset_id)
    if not isinstance(requests, list) or len(requests) > 100:
        reject('request_limit', 'Coverage matrix accepts at most one hundred contexts')
    rows = []
    for index, request in enumerate(requests):
        normalized = algebra.context(request)
        cells = []
        for column in asset['schema']:
            candidates = alternatives(store, asset_id, [column['name']], normalized)
            cells.append({'column': column['name'], 'allowed': candidates['selected'] is not None, 'grant_id': candidates['selected']})
        rows.append({'index': index, 'context': normalized, 'columns': cells, 'all_allowed_individually': all(cell['allowed'] for cell in cells)})
    return {'asset_id': asset_id, 'rows': rows, 'note': 'Individual column coverage does not imply a single joint grant'}


def revocation_impact(store, grant_id):
    grant = grants.get(store, grant_id)
    rows = store.all('SELECT DISTINCT a.artifact_id,a.asset_id,a.build_id,a.status FROM artifacts a JOIN artifact_inputs i ON i.artifact_id=a.artifact_id WHERE i.grant_id=? ORDER BY a.asset_id,a.artifact_id', (grant_id,))
    graph = topology.adjacency(store)
    downstream = topology.descendants(graph, grant['asset_id'])
    plans = []
    for row in store.all('SELECT plan_id,target,payload FROM plans ORDER BY plan_id'):
        payload = json.loads(row['payload'])
        referenced = any(leaf['grant_id'] == grant_id for step in payload['steps'] for leaves in step['lineage'].values() for leaf in leaves)
        if referenced:
            plans.append({'plan_id': row['plan_id'], 'target': row['target']})
    return {'grant_id': grant_id, 'source_asset': grant['asset_id'], 'artifacts': rows, 'valid_artifacts': sum(row['status'] == 'valid' for row in rows), 'downstream_assets': downstream, 'plans': plans}


def expiry_calendar(store, start, end):
    start = timestamp(start)
    end = timestamp(end)
    if start >= end:
        reject('expiry_interval', 'Expiry interval must increase')
    result = []
    for row in store.all("SELECT grant_id FROM grants WHERE state='active' ORDER BY grant_id"):
        grant = grants.get(store, row['grant_id'])
        expiration = grant['policy']['valid_until']
        if start <= expiration < end:
            impact = revocation_impact(store, grant['grant_id'])
            result.append({'grant_id': grant['grant_id'], 'asset_id': grant['asset_id'], 'expires_at': expiration, 'valid_artifacts': impact['valid_artifacts'], 'downstream_assets': impact['downstream_assets']})
    result.sort(key=lambda row: (row['expires_at'], row['grant_id']))
    return result


def overlap(left, right):
    left = algebra.normalize(left)
    right = algebra.normalize(right)
    intersection = algebra.intersect([left, right])
    columns = sorted(set(left['columns']) & set(right['columns']))
    return {
        'overlap': intersection['usable'] and bool(columns),
        'columns': columns,
        'intersection': intersection,
        'left_only_columns': sorted(set(left['columns']) - set(right['columns'])),
        'right_only_columns': sorted(set(right['columns']) - set(left['columns'])),
    }


def conflicting_grants(store, asset_id):
    candidates = grants.for_asset(store, asset_id)
    result = []
    for index, left in enumerate(candidates):
        for right in candidates[index + 1:]:
            comparison = overlap(left['policy'], right['policy'])
            if not comparison['overlap']:
                continue
            obligations_equal = left['policy']['obligations'] == right['policy']['obligations']
            result.append({
                'left': left['grant_id'],
                'right': right['grant_id'],
                'columns': comparison['columns'],
                'different_obligations': not obligations_equal,
                'depth_limits': [left['policy']['max_depth'], right['policy']['max_depth']],
                'selection_rule': 'smallest_covering_column_set_then_grant_identifier',
            })
    return result


def compare_grant_versions(store, grant_id, before, after):
    old = grants.get(store, grant_id, before)
    new = grants.get(store, grant_id, after)
    return {'grant_id': grant_id, 'before': before, 'after': after, 'state_changed': old['state'] != new['state'], 'narrowing': algebra.narrowing(old['policy'], new['policy']), 'columns_removed': sorted(set(old['policy']['columns']) - set(new['policy']['columns'])), 'columns_added': sorted(set(new['policy']['columns']) - set(old['policy']['columns']))}
