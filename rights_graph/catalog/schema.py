from rights_graph.primitives import checksum, count, fields, name, reject, symbols

TYPES = {'string', 'integer', 'decimal', 'boolean', 'timestamp', 'bytes'}
CLASSIFICATION = {'public': 0, 'internal': 1, 'restricted': 2, 'sensitive': 3}


def normalize(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 1000:
        reject('schema_columns', 'Schema requires one to one thousand columns')
    result = []
    seen = set()
    for column in value:
        fields(column, {'name', 'type', 'nullable', 'classification'}, {'tags'})
        column_name = name(column['name'], 'column')
        if column_name in seen:
            reject('schema_duplicate', 'Duplicate column name', column=column_name)
        seen.add(column_name)
        if column['type'] not in TYPES:
            reject('schema_type', 'Unsupported column type', column=column_name)
        if type(column['nullable']) is not bool:
            reject('schema_nullable', 'Nullable must be boolean')
        if column['classification'] not in CLASSIFICATION:
            reject('schema_classification', 'Unknown classification')
        result.append({
            'name': column_name,
            'type': column['type'],
            'nullable': column['nullable'],
            'classification': column['classification'],
            'tags': symbols(column.get('tags', []), 'tags', empty=True),
        })
    return result


def by_name(value):
    return {column['name']: column for column in normalize(value)}


def compatibility(before, after):
    old = by_name(before)
    new = by_name(after)
    breaking = []
    changes = []
    for key in sorted(set(old) | set(new)):
        left = old.get(key)
        right = new.get(key)
        if left is None:
            changes.append({'column': key, 'kind': 'added'})
            if not right['nullable']:
                breaking.append({'column': key, 'reason': 'required_column_added'})
            continue
        if right is None:
            changes.append({'column': key, 'kind': 'removed'})
            breaking.append({'column': key, 'reason': 'column_removed'})
            continue
        if left == right:
            continue
        changes.append({'column': key, 'kind': 'changed', 'before': left, 'after': right})
        if left['type'] != right['type'] and (left['type'], right['type']) != ('integer', 'decimal'):
            breaking.append({'column': key, 'reason': 'incompatible_type'})
        if left['nullable'] and not right['nullable']:
            breaking.append({'column': key, 'reason': 'nullability_narrowed'})
        if CLASSIFICATION[right['classification']] > CLASSIFICATION[left['classification']]:
            breaking.append({'column': key, 'reason': 'classification_increased'})
    return {'compatible': not breaking, 'breaking': breaking, 'changes': changes}


def maximum_classification(columns):
    if not columns:
        return 'public'
    return max((column['classification'] for column in columns), key=CLASSIFICATION.__getitem__)


def project(schema, names):
    indexed = by_name(schema)
    selected = symbols(names, 'columns')
    missing = sorted(set(selected) - set(indexed))
    if missing:
        reject('schema_missing', 'Requested columns do not exist', columns=missing)
    return [indexed[column] for column in selected]
