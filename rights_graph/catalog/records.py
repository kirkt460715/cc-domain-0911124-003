import base64
import json
from decimal import Decimal, InvalidOperation
from rights_graph.primitives import canonical, checksum, count, fields, name, reject, timestamp
from rights_graph.catalog import assets, schema
from rights_graph.journal import audit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS data_batches(
 batch_id TEXT PRIMARY KEY,asset_id TEXT NOT NULL,asset_version INTEGER NOT NULL,
 row_count INTEGER NOT NULL,digest TEXT NOT NULL,created_at TEXT NOT NULL,
 FOREIGN KEY(asset_id,asset_version) REFERENCES asset_versions(asset_id,version));
CREATE TABLE IF NOT EXISTS data_rows(
 batch_id TEXT NOT NULL REFERENCES data_batches(batch_id),row_index INTEGER NOT NULL,
 payload TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(batch_id,row_index));
'''


def typed_value(value, column):
    if value is None:
        if not column['nullable']:
            reject('null_denied', 'Column does not permit null', column=column['name'])
        return None
    kind = column['type']
    if kind == 'string':
        if not isinstance(value, str) or len(value) > 1000000:
            reject('row_string', 'Expected bounded string', column=column['name'])
        return value
    if kind == 'integer':
        if type(value) is not int or abs(value) > 2**53 - 1:
            reject('row_integer', 'Expected exact bounded integer', column=column['name'])
        return value
    if kind == 'boolean':
        if type(value) is not bool:
            reject('row_boolean', 'Expected boolean', column=column['name'])
        return value
    if kind == 'decimal':
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            reject('row_decimal', 'Expected finite decimal', column=column['name'])
        try:
            parsed = Decimal(str(value))
        except InvalidOperation as exc:
            from rights_graph.primitives import GraphError
            raise GraphError('row_decimal', 'Malformed decimal') from exc
        if not parsed.is_finite() or abs(parsed) > Decimal('1e30'):
            reject('row_decimal', 'Decimal outside supported range')
        if parsed.as_tuple().exponent < -18:
            reject('row_decimal', 'Decimal scale exceeds eighteen places')
        text = format(parsed, 'f')
        return (text.rstrip('0').rstrip('.') if '.' in text else text) if parsed else '0'
    if kind == 'timestamp':
        return timestamp(value)
    if kind == 'bytes':
        if not isinstance(value, str) or len(value) > 2000000:
            reject('row_bytes', 'Bytes are represented by bounded base64 string')
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            from rights_graph.primitives import GraphError
            raise GraphError('row_bytes', 'Malformed base64 value') from exc
        return base64.b64encode(decoded).decode()
    reject('row_type', 'Unknown column type')


def normalize_row(value, columns):
    if not isinstance(value, dict):
        reject('row_object', 'Each data row must be an object')
    known = {column['name'] for column in columns}
    if set(value) - known:
        reject('row_unknown_columns', 'Row contains unknown columns', columns=sorted(set(value) - known))
    result = {}
    for column in columns:
        if column['name'] not in value and not column['nullable']:
            reject('row_missing_column', 'Required column is missing', column=column['name'])
        result[column['name']] = typed_value(value.get(column['name']), column)
    return result


class DataCatalog:
    def __init__(self, store):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize data catalog outside transaction')
        store.db.executescript(SCHEMA)

    def import_rows(self, batch_id, asset_id, version, rows):
        name(batch_id, 'batch_id')
        count(version, 'version', 1)
        if not isinstance(rows, list) or len(rows) > 100000:
            reject('data_rows', 'Batch must contain at most one hundred thousand rows')
        with self.store.atomic():
            asset = assets.get(self.store, asset_id, version)
            if asset['kind'] != 'source' or asset['state'] != 'active':
                reject('data_source', 'Rows may be loaded only for active source assets')
            normalized = [normalize_row(row, asset['schema']) for row in rows]
            sha = checksum(normalized)
            existing = self.store.one('SELECT * FROM data_batches WHERE batch_id=?', (batch_id,))
            if existing:
                if (existing['asset_id'], existing['asset_version'], existing['digest']) == (asset_id, version, sha):
                    return {**existing, 'duplicate': True}
                reject('data_batch_conflict', 'Data batch identifier is already bound to different content')
            self.store.execute('INSERT INTO data_batches(batch_id,asset_id,asset_version,row_count,digest,created_at) VALUES(?,?,?,?,?,?)', (batch_id, asset_id, version, len(normalized), sha, self.store.clock()))
            for index, row in enumerate(normalized):
                self.store.execute('INSERT INTO data_rows(batch_id,row_index,payload,digest) VALUES(?,?,?,?)', (batch_id, index, canonical(row), checksum(row)))
            audit.append(self.store, 'data.imported', {'batch_id': batch_id, 'asset_id': asset_id, 'version': version, 'rows': len(normalized), 'digest': sha})
            return self.get(batch_id)

    def get(self, batch_id):
        row = self.store.one('SELECT * FROM data_batches WHERE batch_id=?', (batch_id,))
        if row is None:
            reject('unknown_data_batch', 'Source data batch does not exist')
        return row

    def rows(self, batch_id, *, after=-1, limit=1000):
        self.get(batch_id)
        count(after, 'after', -1)
        count(limit, 'limit', 1, 100000)
        result = self.store.all('SELECT row_index,payload,digest FROM data_rows WHERE batch_id=? AND row_index>? ORDER BY row_index LIMIT ?', (batch_id, after, limit))
        for row in result:
            row['payload'] = json.loads(row['payload'])
            if checksum(row['payload']) != row['digest']:
                reject('data_row_corrupt', 'Source data row checksum mismatch', batch_id=batch_id, row_index=row['row_index'])
        return result

    def verify(self, batch_id):
        batch = self.get(batch_id)
        rows = self.rows(batch_id, limit=100000)
        if [row['row_index'] for row in rows] != list(range(batch['row_count'])):
            reject('data_row_order', 'Source data row sequence is incomplete')
        actual = checksum([row['payload'] for row in rows])
        if actual != batch['digest']:
            reject('data_batch_corrupt', 'Source data batch checksum mismatch')
        return {'ok': True, 'batch_id': batch_id, 'rows': len(rows), 'digest': actual}

    def listing(self, asset_id=None):
        if asset_id is None:
            return self.store.all('SELECT * FROM data_batches ORDER BY asset_id,asset_version,batch_id')
        assets.get(self.store, asset_id)
        return self.store.all('SELECT * FROM data_batches WHERE asset_id=? ORDER BY asset_version,batch_id', (asset_id,))
