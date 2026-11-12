import csv
import io
import json
from rights_graph.catalog import assets, schema
from rights_graph.primitives import canonical, checksum, count, reject


def decode_cell(raw, column, null_token):
    if raw == null_token:
        return None
    kind = column['type']
    if kind == 'integer':
        if not raw or raw.strip() != raw:
            reject('csv_integer', 'Integer cells must have no whitespace')
        try:
            value = int(raw)
        except ValueError as exc:
            from rights_graph.primitives import GraphError
            raise GraphError('csv_integer', 'Invalid integer cell') from exc
        if str(value) != raw:
            reject('csv_integer', 'Integer cells must use canonical decimal notation')
        return value
    if kind == 'boolean':
        if raw not in {'true', 'false'}:
            reject('csv_boolean', 'Boolean cells must be true or false')
        return raw == 'true'
    return raw


def import_csv(data_catalog, batch_id, asset_id, version, text, *, null_token='\\N', maximum_rows=100000):
    if not isinstance(text, str) or len(text.encode('utf-8')) > 16777216:
        reject('csv_size', 'CSV input is invalid or exceeds maximum size')
    if not isinstance(null_token, str) or not null_token or any(char in null_token for char in '\r\n,'):
        reject('csv_null', 'Null token must be a nonempty simple string')
    count(maximum_rows, 'maximum_rows', 1, 100000)
    asset = assets.get(data_catalog.store, asset_id, version)
    columns = schema.by_name(asset['schema'])
    reader = csv.reader(io.StringIO(text, newline=''), strict=True)
    try:
        header = next(reader)
    except StopIteration:
        reject('csv_header', 'CSV input has no header')
    except csv.Error as exc:
        from rights_graph.primitives import GraphError
        raise GraphError('csv_parse', str(exc)) from exc
    if len(header) != len(set(header)) or set(header) != set(columns):
        reject('csv_header', 'CSV header must cover each source column exactly once')
    rows = []
    try:
        for ordinal, cells in enumerate(reader, 1):
            if ordinal > maximum_rows:
                reject('csv_rows', 'CSV input exceeds row limit')
            if len(cells) != len(header):
                reject('csv_width', 'CSV row width differs from header', row=ordinal)
            rows.append({column: decode_cell(raw, columns[column], null_token) for column, raw in zip(header, cells)})
    except csv.Error as exc:
        from rights_graph.primitives import GraphError
        raise GraphError('csv_parse', str(exc)) from exc
    return data_catalog.import_rows(batch_id, asset_id, version, rows)


def export_csv(preview_engine, preview_id, artifact_id, *, null_token='\\N'):
    exported = preview_engine.export(preview_id, artifact_id)
    payload = exported['data']['payload']
    from rights_graph.planner.plans import get
    plan = get(preview_engine.store, payload['plan_id'])
    columns = plan['payload']['steps'][-1]['columns']
    rows = payload['rows']
    buffer = io.StringIO(newline='')
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        cells = []
        for column in columns:
            value = row[column]
            if value is None:
                cells.append(null_token)
            elif isinstance(value, bool):
                cells.append('true' if value else 'false')
            else:
                text = str(value)
                if text == null_token:
                    reject('csv_null_collision', 'A real cell equals the configured null token')
                cells.append(text)
        writer.writerow(cells)
    text = buffer.getvalue()
    import hashlib
    return {'csv': text, 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(), 'columns': columns, 'row_count': len(rows), 'authorization': exported['authorization']}


def export_jsonlines(preview_engine, preview_id, artifact_id):
    exported = preview_engine.export(preview_id, artifact_id)
    rows = exported['data']['payload']['rows']
    text = ''.join(canonical(row) + '\n' for row in rows)
    import hashlib
    return {'jsonlines': text, 'sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(), 'row_count': len(rows), 'authorization': exported['authorization']}


def import_jsonlines(data_catalog, batch_id, asset_id, version, text, maximum_rows=100000):
    from rights_graph.primitives import json_loads
    count(maximum_rows, 'maximum_rows', 1, 100000)
    if not isinstance(text, str) or len(text.encode('utf-8')) > 16777216:
        reject('jsonlines_size', 'JSON-lines input exceeds maximum size')
    rows = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            reject('jsonlines_blank', 'JSON-lines records cannot be blank', line=number)
        if len(rows) >= maximum_rows:
            reject('jsonlines_rows', 'JSON-lines input exceeds row limit')
        value = json_loads(raw)
        if not isinstance(value, dict):
            reject('jsonlines_object', 'Each JSON-lines record must be an object', line=number)
        rows.append(value)
    return data_catalog.import_rows(batch_id, asset_id, version, rows)
