import datetime as dt
import hashlib
import json
import re


class GraphError(Exception):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.details = details

    def json(self):
        return {'code': self.code, 'message': str(self), 'details': self.details}


def reject(code, message, **details):
    raise GraphError(code, message, **details)


def name(value, field='name'):
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.:-]{0,99}', value):
        reject('invalid_name', 'Invalid symbolic name', field=field)
    return value


def count(value, field, minimum=0, maximum=1000000):
    if type(value) is not int or not minimum <= value <= maximum:
        reject('invalid_count', 'Expected bounded integer', field=field)
    return value


def label(value, field, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        reject('invalid_text', 'Expected nonempty bounded text', field=field)
    if any(ord(c) < 32 for c in value):
        reject('invalid_text', 'Text cannot contain control characters', field=field)
    return value.strip()


def fields(value, required, optional=()):
    if not isinstance(value, dict):
        reject('invalid_object', 'Expected object')
    missing = set(required) - set(value)
    unknown = set(value) - set(required) - set(optional)
    if missing or unknown:
        reject('invalid_fields', 'Object does not match schema', missing=sorted(missing), unknown=sorted(unknown))
    return value


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise GraphError('invalid_json', 'Value is not canonical JSON') from exc


def checksum(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def timestamp(value):
    if not isinstance(value, str):
        reject('invalid_time', 'Timestamp must be text')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise GraphError('invalid_time', 'Malformed timestamp') from exc
    if parsed.tzinfo is None:
        reject('invalid_time', 'Timestamp requires timezone')
    return parsed.astimezone(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def symbols(value, field, *, empty=False):
    if not isinstance(value, list) or len(value) > 1000 or (not value and not empty):
        reject('invalid_set', 'Expected bounded symbol list', field=field)
    normalized = [name(item, field) for item in value]
    if len(normalized) != len(set(normalized)):
        reject('duplicate_symbol', 'Symbol list contains duplicates', field=field)
    return sorted(normalized)


def json_loads(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                reject('duplicate_key', 'JSON object has duplicate key', key=key)
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=unique, parse_constant=lambda value: reject('malformed_json', 'Nonfinite JSON numbers are forbidden'))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GraphError('malformed_json', 'Cannot decode JSON') from exc
