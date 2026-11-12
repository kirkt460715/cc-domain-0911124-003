from rights_graph.primitives import count, fields, name, reject, symbols, timestamp

DIMENSIONS = ('purposes', 'regions', 'rights')
RIGHTS = {'read', 'transform', 'distribute', 'train'}


def normalize(policy):
    fields(policy, {'purposes', 'regions', 'rights', 'valid_from', 'valid_until', 'obligations', 'columns'}, {'max_depth', 'allow_derivatives'})
    start = timestamp(policy['valid_from'])
    end = timestamp(policy['valid_until'])
    if start >= end:
        reject('policy_interval', 'Policy interval must be nonempty')
    rights = symbols(policy['rights'], 'rights')
    if set(rights) - RIGHTS:
        reject('policy_right', 'Unknown declared right')
    derivatives = policy.get('allow_derivatives', True)
    if type(derivatives) is not bool:
        reject('policy_derivatives', 'allow_derivatives must be boolean')
    return {
        'purposes': symbols(policy['purposes'], 'purposes'),
        'regions': symbols(policy['regions'], 'regions'),
        'rights': rights,
        'valid_from': start,
        'valid_until': end,
        'obligations': symbols(policy['obligations'], 'obligations', empty=True),
        'columns': symbols(policy['columns'], 'columns'),
        'max_depth': count(policy.get('max_depth', 32), 'max_depth', 0, 1000),
        'allow_derivatives': derivatives,
    }


def intersect(policies):
    policies = list(policies)
    if not policies:
        reject('policy_empty', 'Cannot derive authorization without a source policy')
    result = {
        'purposes': list(policies[0]['purposes']),
        'regions': list(policies[0]['regions']),
        'rights': list(policies[0]['rights']),
        'valid_from': policies[0]['valid_from'],
        'valid_until': policies[0]['valid_until'],
        'obligations': [],
        'max_depth': policies[0]['max_depth'],
        'allow_derivatives': True,
    }
    for policy in policies:
        for dimension in DIMENSIONS:
            result[dimension] = sorted(set(result[dimension]) & set(policy[dimension]))
        result['valid_from'] = max(result['valid_from'], policy['valid_from'])
        result['valid_until'] = min(result['valid_until'], policy['valid_until'])
        result['obligations'] = sorted(set(result['obligations']) | set(policy['obligations']))
        result['max_depth'] = min(result['max_depth'], policy['max_depth'])
        result['allow_derivatives'] = result['allow_derivatives'] and policy['allow_derivatives']
    result['usable'] = (
        all(result[dimension] for dimension in DIMENSIONS)
        and result['valid_from'] < result['valid_until']
    )
    return result


def context(value):
    fields(value, {'purpose', 'region', 'right', 'at', 'fulfilled_obligations'}, {'maximum_classification'})
    right = name(value['right'], 'right')
    if right not in RIGHTS:
        reject('context_right', 'Unknown requested right')
    classification = value.get('maximum_classification', 'sensitive')
    from rights_graph.catalog.schema import CLASSIFICATION
    if classification not in CLASSIFICATION:
        reject('context_classification', 'Unknown classification ceiling')
    return {
        'purpose': name(value['purpose'], 'purpose'),
        'region': name(value['region'], 'region'),
        'right': right,
        'at': timestamp(value['at']),
        'fulfilled_obligations': symbols(value['fulfilled_obligations'], 'obligations', empty=True),
        'maximum_classification': classification,
    }


def evaluate(policy, request, *, depth=0):
    request = context(request)
    count(depth, 'depth', 0, 1000)
    reasons = []
    for plural, singular in [('purposes', 'purpose'), ('regions', 'region'), ('rights', 'right')]:
        if request[singular] not in policy[plural]:
            reasons.append({'code': singular + '_denied', 'requested': request[singular], 'allowed': policy[plural]})
    if request['at'] < policy['valid_from']:
        reasons.append({'code': 'not_yet_valid', 'valid_from': policy['valid_from']})
    if request['at'] >= policy['valid_until']:
        reasons.append({'code': 'expired', 'valid_until': policy['valid_until']})
    missing = sorted(set(policy['obligations']) - set(request['fulfilled_obligations']))
    if missing:
        reasons.append({'code': 'obligations_unfulfilled', 'obligations': missing})
    if depth > policy['max_depth']:
        reasons.append({'code': 'derivation_depth', 'actual': depth, 'maximum': policy['max_depth']})
    if depth and not policy['allow_derivatives']:
        reasons.append({'code': 'derivatives_denied'})
    return {'allowed': not reasons, 'reasons': reasons, 'context': request}


def narrowing(before, after):
    removed = {}
    added = {}
    for dimension in DIMENSIONS:
        removed[dimension] = sorted(set(before[dimension]) - set(after[dimension]))
        added[dimension] = sorted(set(after[dimension]) - set(before[dimension]))
    return {
        'removed': removed,
        'added': added,
        'start_delayed': after['valid_from'] > before['valid_from'],
        'expiry_shortened': after['valid_until'] < before['valid_until'],
        'new_obligations': sorted(set(after['obligations']) - set(before['obligations'])),
        'depth_reduced': after['max_depth'] < before['max_depth'],
        'derivatives_removed': before['allow_derivatives'] and not after['allow_derivatives'],
    }
