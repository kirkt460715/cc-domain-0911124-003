import json
from rights_graph.primitives import canonical, checksum, count, fields, label, name, reject
from rights_graph.catalog import schema
from rights_graph.journal import audit


def get(store, asset_id, version=None):
    name(asset_id, 'asset_id')
    asset = store.one('SELECT * FROM assets WHERE asset_id=?', (asset_id,))
    if asset is None:
        reject('unknown_asset', 'Asset does not exist', asset_id=asset_id)
    version = asset['head'] if version is None else count(version, 'version', 1)
    row = store.one('SELECT * FROM asset_versions WHERE asset_id=? AND version=?', (asset_id, version))
    if row is None:
        reject('unknown_version', 'Asset version does not exist', asset_id=asset_id, version=version)
    return {
        **asset,
        'version': version,
        'schema': json.loads(row['schema_json']),
        'description': row['description'],
        'content_hash': row['content_hash'],
        'metadata': json.loads(row['metadata']),
        'version_created_at': row['created_at'],
    }


def create(store, asset_id, kind, owner, columns, description, *, metadata=None, content_hash=None):
    name(asset_id, 'asset_id')
    name(owner, 'owner')
    if kind not in {'source', 'derived'}:
        reject('asset_kind', 'Asset must be source or derived')
    normalized = schema.normalize(columns)
    description = label(description, 'description')
    metadata = {} if metadata is None else metadata
    if not isinstance(metadata, dict):
        reject('asset_metadata', 'Asset metadata must be an object')
    canonical(metadata)
    if content_hash is None:
        content_hash = checksum({'schema': normalized, 'metadata': metadata, 'description': description})
    validate_hash(content_hash)
    with store.atomic():
        if store.one('SELECT asset_id FROM assets WHERE asset_id=?', (asset_id,)):
            reject('asset_exists', 'Asset already exists')
        store.execute('INSERT INTO assets(asset_id,kind,head,state,owner,created_at) VALUES(?,?,1,?,?,?)', (asset_id, kind, 'active', owner, store.clock()))
        store.execute('INSERT INTO asset_versions(asset_id,version,schema_json,description,content_hash,metadata,created_at) VALUES(?,1,?,?,?,?,?)', (asset_id, canonical(normalized), description, content_hash, canonical(metadata), store.clock()))
        audit.append(store, 'asset.created', {'asset_id': asset_id, 'kind': kind, 'content_hash': content_hash})
        return get(store, asset_id)


def validate_hash(value):
    if not isinstance(value, str) or len(value) != 64 or any(char not in '0123456789abcdef' for char in value):
        reject('content_hash', 'Content hash must be lowercase SHA256')
    return value


def revise(store, asset_id, expected_head, columns, description, *, metadata=None, content_hash=None, allow_breaking=False):
    count(expected_head, 'expected_head', 1)
    normalized = schema.normalize(columns)
    description = label(description, 'description')
    metadata = {} if metadata is None else metadata
    if not isinstance(metadata, dict):
        reject('asset_metadata', 'Asset metadata must be object')
    canonical(metadata)
    content_hash = content_hash or checksum({'schema': normalized, 'metadata': metadata, 'description': description})
    validate_hash(content_hash)
    with store.atomic():
        previous = get(store, asset_id)
        if previous['head'] != expected_head:
            reject('stale_head', 'Asset head changed')
        if previous['state'] != 'active':
            reject('asset_retired', 'Retired asset cannot be revised')
        compatibility = schema.compatibility(previous['schema'], normalized)
        if not compatibility['compatible'] and not allow_breaking:
            reject('breaking_schema', 'Schema change requires explicit breaking acknowledgement', compatibility=compatibility)
        version = expected_head + 1
        store.execute('INSERT INTO asset_versions(asset_id,version,schema_json,description,content_hash,metadata,created_at) VALUES(?,?,?,?,?,?,?)', (asset_id, version, canonical(normalized), description, content_hash, canonical(metadata), store.clock()))
        store.execute('UPDATE assets SET head=? WHERE asset_id=?', (version, asset_id))
        from rights_graph.planner.invalidation import invalidate_asset
        affected = invalidate_asset(store, asset_id, 'asset_revised', only_unpinned=True)
        audit.append(store, 'asset.revised', {'asset_id': asset_id, 'version': version, 'compatibility': compatibility, 'invalidated': affected})
        return get(store, asset_id)


def retire(store, asset_id, expected_head, reason):
    reason = label(reason, 'reason')
    with store.atomic():
        previous = get(store, asset_id)
        if previous['head'] != expected_head:
            reject('stale_head', 'Asset head changed')
        if previous['state'] == 'retired':
            return previous
        store.execute("UPDATE assets SET state='retired' WHERE asset_id=?", (asset_id,))
        from rights_graph.planner.invalidation import invalidate_asset
        affected = invalidate_asset(store, asset_id, 'asset_retired')
        audit.append(store, 'asset.retired', {'asset_id': asset_id, 'reason': reason, 'invalidated': affected})
        return get(store, asset_id)


def listing(store, kind=None, owner=None):
    conditions = []
    parameters = []
    if kind is not None:
        if kind not in {'source', 'derived'}:
            reject('asset_kind', 'Unknown asset kind')
        conditions.append('kind=?')
        parameters.append(kind)
    if owner is not None:
        conditions.append('owner=?')
        parameters.append(name(owner, 'owner'))
    where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
    rows = store.all(f'SELECT asset_id FROM assets{where} ORDER BY asset_id', parameters)
    return [get(store, row['asset_id']) for row in rows]


def versions(store, asset_id):
    get(store, asset_id)
    rows = store.all('SELECT version FROM asset_versions WHERE asset_id=? ORDER BY version', (asset_id,))
    return [get(store, asset_id, row['version']) for row in rows]
