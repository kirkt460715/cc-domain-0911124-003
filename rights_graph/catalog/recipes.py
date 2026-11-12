import json
from rights_graph.primitives import canonical, checksum, count, fields, label, name, reject, symbols
from rights_graph.catalog import assets, schema
from rights_graph.planner import topology
from rights_graph.journal import audit

OPERATORS = {'copy', 'concat', 'hash', 'aggregate', 'constant', 'redact'}


def normalize(store, output_asset, value):
    fields(value, {'inputs', 'columns', 'description'})
    output = assets.get(store, output_asset)
    if output['kind'] != 'derived':
        reject('recipe_output', 'Recipe output must be a derived asset')
    inputs = value['inputs']
    columns = value['columns']
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 100:
        reject('recipe_inputs', 'Recipe needs one to one hundred inputs')
    if not isinstance(columns, list) or not columns:
        reject('recipe_columns', 'Recipe needs output column rules')
    aliases = {}
    normalized_inputs = []
    for input_spec in inputs:
        fields(input_spec, {'asset_id', 'alias'}, {'version'})
        alias = name(input_spec['alias'], 'alias')
        if alias in aliases:
            reject('recipe_alias', 'Input alias is repeated')
        asset_id = name(input_spec['asset_id'], 'asset_id')
        version = input_spec.get('version')
        if version is not None:
            count(version, 'version', 1)
        asset = assets.get(store, asset_id, version)
        if asset['state'] != 'active':
            reject('recipe_retired_input', 'Recipe cannot reference retired asset')
        aliases[alias] = asset
        normalized_inputs.append({'asset_id': asset_id, 'alias': alias, 'version': version})
    expected = schema.by_name(output['schema'])
    mapped = set()
    normalized_columns = []
    for column in columns:
        fields(column, {'output', 'operator', 'sources'}, {'constant', 'reason'})
        target = name(column['output'], 'output_column')
        if target not in expected or target in mapped:
            reject('recipe_mapping', 'Output column is unknown or repeated', column=target)
        mapped.add(target)
        operator = column['operator']
        if operator not in OPERATORS:
            reject('recipe_operator', 'Unsupported lineage operator')
        references = column['sources']
        if not isinstance(references, list) or len(references) > 100:
            reject('recipe_sources', 'Column sources must be bounded list')
        parsed = []
        source_columns = []
        for reference in references:
            fields(reference, {'input', 'column'})
            alias = name(reference['input'], 'input')
            source_name = name(reference['column'], 'column')
            if alias not in aliases:
                reject('recipe_input', 'Unknown input alias', alias=alias)
            indexed = schema.by_name(aliases[alias]['schema'])
            if source_name not in indexed:
                reject('recipe_source_column', 'Unknown source column', alias=alias, column=source_name)
            parsed.append({'input': alias, 'column': source_name})
            source_columns.append(indexed[source_name])
        keys = [(row['input'], row['column']) for row in parsed]
        if len(keys) != len(set(keys)):
            reject('recipe_source_duplicate', 'Column source repeats')
        if operator == 'constant':
            if references or 'constant' not in column:
                reject('recipe_constant', 'Constant output requires value and no data sources')
            canonical(column['constant'])
        elif not references:
            reject('recipe_sources', 'Nonconstant output requires sources')
        if operator in {'copy', 'hash', 'redact'} and len(references) != 1:
            reject('recipe_arity', 'Operator requires exactly one source')
        target_type = expected[target]['type']
        if operator == 'copy' and source_columns[0]['type'] != target_type:
            reject('recipe_type', 'Copy must preserve source type')
        if operator in {'hash', 'concat'} and target_type != 'string':
            reject('recipe_type', 'Hash and concatenation produce strings')
        if operator == 'aggregate' and target_type not in {'integer', 'decimal'}:
            reject('recipe_type', 'Aggregate output must be numeric')
        if operator not in {'redact', 'constant'}:
            required = schema.maximum_classification(source_columns)
            if schema.CLASSIFICATION[expected[target]['classification']] < schema.CLASSIFICATION[required]:
                reject('recipe_downgrade', 'Classification cannot silently decrease', column=target)
        reason = column.get('reason')
        if operator == 'redact':
            reason = label(reason, 'redaction_reason')
        normalized = {'output': target, 'operator': operator, 'sources': parsed}
        if operator == 'constant':
            normalized['constant'] = column['constant']
        if reason is not None:
            normalized['reason'] = label(reason, 'reason')
        normalized_columns.append(normalized)
    if mapped != set(expected):
        reject('recipe_incomplete', 'Every output column needs a lineage rule', missing=sorted(set(expected) - mapped))
    graph = topology.adjacency(store, (output_asset, [row['asset_id'] for row in normalized_inputs]))
    topology.ordered(graph)
    return {'inputs': sorted(normalized_inputs, key=lambda row: row['alias']), 'columns': sorted(normalized_columns, key=lambda row: row['output']), 'description': label(value['description'], 'description')}


def get(store, recipe_id):
    name(recipe_id, 'recipe_id')
    row = store.one('SELECT * FROM recipes WHERE recipe_id=?', (recipe_id,))
    if row is None:
        reject('unknown_recipe', 'Recipe does not exist')
    row['definition'] = json.loads(row['definition'])
    return row


def for_output(store, asset_id):
    row = store.one('SELECT recipe_id FROM recipes WHERE output_asset=?', (asset_id,))
    if row is None:
        reject('missing_recipe', 'Derived asset has no recipe', asset_id=asset_id)
    return get(store, row['recipe_id'])


def put(store, recipe_id, output_asset, expected_revision, definition):
    name(recipe_id, 'recipe_id')
    count(expected_revision, 'expected_revision')
    with store.atomic():
        previous = store.one('SELECT * FROM recipes WHERE recipe_id=?', (recipe_id,))
        actual_revision = previous['revision'] if previous else 0
        if actual_revision != expected_revision:
            reject('stale_recipe', 'Recipe revision changed')
        if previous and previous['output_asset'] != output_asset:
            reject('recipe_identity', 'Recipe output cannot change')
        occupied = store.one('SELECT recipe_id FROM recipes WHERE output_asset=?', (output_asset,))
        if occupied and occupied['recipe_id'] != recipe_id:
            reject('recipe_output_conflict', 'Output already has another recipe')
        normalized = normalize(store, output_asset, definition)
        revision = expected_revision + 1
        sha = checksum(normalized)
        store.execute(
            "INSERT INTO recipes(recipe_id,output_asset,revision,definition,digest,state,updated_at) VALUES(?,?,?,?,?,'active',?) "
            'ON CONFLICT(recipe_id) DO UPDATE SET revision=excluded.revision,definition=excluded.definition,digest=excluded.digest,updated_at=excluded.updated_at',
            (recipe_id, output_asset, revision, canonical(normalized), sha, store.clock()),
        )
        store.execute('DELETE FROM dependencies WHERE recipe_id=?', (recipe_id,))
        for row in normalized['inputs']:
            store.execute('INSERT INTO dependencies(recipe_id,input_asset,alias,pinned_version) VALUES(?,?,?,?)', (recipe_id, row['asset_id'], row['alias'], row['version']))
        store.execute('INSERT INTO recipe_versions(recipe_id,revision,definition,digest) VALUES(?,?,?,?)', (recipe_id, revision, canonical(normalized), sha))
        from rights_graph.planner.invalidation import invalidate_asset
        invalidated = invalidate_asset(store, output_asset, 'recipe_changed')
        audit.append(store, 'recipe.updated', {'recipe_id': recipe_id, 'revision': revision, 'invalidated': invalidated})
        return get(store, recipe_id)


def listing(store):
    return [get(store, row['recipe_id']) for row in store.all('SELECT recipe_id FROM recipes ORDER BY recipe_id')]


def history(store, recipe_id):
    get(store, recipe_id)
    rows = store.all('SELECT * FROM recipe_versions WHERE recipe_id=? ORDER BY revision', (recipe_id,))
    for row in rows:
        row['definition'] = json.loads(row['definition'])
    return rows
