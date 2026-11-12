import json
from rights_graph.primitives import canonical, checksum, fields, reject
from rights_graph.catalog import assets, recipes
from rights_graph.policy import grants
from rights_graph.journal import audit


def import_catalog(store, value):
    fields(value, {'format', 'version', 'assets', 'grants', 'recipes'})
    if value['format'] != 'rights-catalog' or type(value['version']) is not int or value['version'] != 1:
        reject('catalog_format', 'Unsupported catalog import format')
    for key in ('assets', 'grants', 'recipes'):
        if not isinstance(value[key], list) or len(value[key]) > 10000:
            reject('catalog_size', 'Catalog collection exceeds supported size', collection=key)
    result = {'assets': [], 'grants': [], 'recipes': []}
    with store.atomic():
        for asset in value['assets']:
            fields(asset, {'asset_id', 'kind', 'owner', 'columns', 'description'}, {'metadata', 'content_hash'})
            created = assets.create(store, **asset)
            result['assets'].append(created['asset_id'])
        for grant in value['grants']:
            fields(grant, {'grant_id', 'asset_id', 'policy'})
            created = grants.create(store, **grant)
            result['grants'].append(created['grant_id'])
        for recipe in value['recipes']:
            fields(recipe, {'recipe_id', 'output_asset', 'definition'})
            created = recipes.put(store, expected_revision=0, **recipe)
            result['recipes'].append(created['recipe_id'])
        audit.append(store, 'catalog.imported', {'digest': checksum(value), 'counts': {key: len(items) for key, items in result.items()}})
        return result


def export_catalog(store):
    result = {'format': 'rights-catalog', 'version': 1, 'assets': [], 'grants': [], 'recipes': []}
    with store.atomic():
        for asset in assets.listing(store):
            if asset['state'] != 'active':
                continue
            result['assets'].append({
                'asset_id': asset['asset_id'],
                'kind': asset['kind'],
                'owner': asset['owner'],
                'columns': asset['schema'],
                'description': asset['description'],
                'metadata': asset['metadata'],
                'content_hash': asset['content_hash'],
            })
        included = {asset['asset_id'] for asset in result['assets']}
        for row in store.all("SELECT grant_id FROM grants WHERE state='active' ORDER BY grant_id"):
            grant = grants.get(store, row['grant_id'])
            if grant['asset_id'] in included:
                result['grants'].append({'grant_id': grant['grant_id'], 'asset_id': grant['asset_id'], 'policy': grant['policy']})
        for recipe in recipes.listing(store):
            if recipe['output_asset'] not in included:
                continue
            if any(item['asset_id'] not in included for item in recipe['definition']['inputs']):
                reject('catalog_retired_dependency', 'Active recipe references retired input')
            if any(item['version'] is not None for item in recipe['definition']['inputs']):
                reject('catalog_pinned_export', 'Portable catalog export requires unpinned inputs; use attestations for pinned version evidence')
            result['recipes'].append({'recipe_id': recipe['recipe_id'], 'output_asset': recipe['output_asset'], 'definition': recipe['definition']})
        return {'catalog': result, 'sha256': checksum(result), 'scope': 'active_configuration_heads_as_new_catalog'}


def verify_catalog_export(value):
    fields(value, {'catalog', 'sha256', 'scope'})
    if checksum(value['catalog']) != value['sha256']:
        reject('catalog_integrity', 'Catalog export digest mismatch')
    return {'ok': True, 'assets': len(value['catalog']['assets']), 'grants': len(value['catalog']['grants']), 'recipes': len(value['catalog']['recipes'])}


def compare_catalogs(left, right):
    verify_catalog_export(left)
    verify_catalog_export(right)
    changes = []
    for collection, key in [('assets', 'asset_id'), ('grants', 'grant_id'), ('recipes', 'recipe_id')]:
        before = {row[key]: row for row in left['catalog'][collection]}
        after = {row[key]: row for row in right['catalog'][collection]}
        for identity in sorted(set(before) | set(after)):
            if before.get(identity) != after.get(identity):
                changes.append({'collection': collection, 'identity': identity, 'before': before.get(identity), 'after': after.get(identity)})
    return {'changes': changes, 'count': len(changes), 'before': left['sha256'], 'after': right['sha256']}
