import json
from rights_graph.primitives import canonical, checksum, count, name


def append(store, action, body):
    name(action, 'action')
    previous = store.scalar('SELECT entry_hash FROM audit ORDER BY position DESC LIMIT 1') or '0' * 64
    at = store.clock()
    encoded = canonical(body)
    entry_hash = checksum([previous, action, encoded, at])
    store.execute('INSERT INTO audit(action,body,at,previous_hash,entry_hash) VALUES(?,?,?,?,?)', (action, encoded, at, previous, entry_hash))
    return entry_hash


def verify(store):
    previous = '0' * 64
    total = 0
    for row in store.execute('SELECT * FROM audit ORDER BY position'):
        expected = checksum([previous, row['action'], row['body'], row['at']])
        if row['previous_hash'] != previous or row['entry_hash'] != expected:
            return {'ok': False, 'broken_at': row['position'], 'count': total}
        previous = expected
        total += 1
    return {'ok': True, 'count': total, 'head': previous}


def page(store, after=0, limit=100):
    count(after, 'after')
    count(limit, 'limit', 1, 1000)
    rows = store.all('SELECT * FROM audit WHERE position>? ORDER BY position LIMIT ?', (after, limit))
    for row in rows:
        row['body'] = json.loads(row['body'])
    return rows
