import json
from rights_graph.primitives import canonical, checksum, fields, name, reject, timestamp
from rights_graph.planner import artifacts, builds, plans
from rights_graph.journal import audit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS deliveries(
 delivery_id TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,recipient TEXT NOT NULL,
 context TEXT NOT NULL,export_id TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,
 state TEXT NOT NULL,created_at TEXT NOT NULL,acknowledged_at TEXT,acknowledgement TEXT);
CREATE TABLE IF NOT EXISTS delivery_alerts(
 alert_id TEXT PRIMARY KEY,delivery_id TEXT NOT NULL,reason TEXT NOT NULL,
 payload TEXT NOT NULL,created_at TEXT NOT NULL,acknowledged_at TEXT);
'''


class DeliveryDesk:
    def __init__(self, store):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize delivery desk outside transaction')
        store.db.executescript(SCHEMA)

    def prepare(self, delivery_id, artifact_id, recipient, request):
        from rights_graph.policy.algebra import context
        name(delivery_id, 'delivery_id')
        name(recipient, 'recipient')
        request = context(request)
        if request['right'] != 'distribute':
            reject('delivery_right', 'Delivery requires explicit distribution authorization')
        with self.store.atomic():
            existing = self.store.one('SELECT * FROM deliveries WHERE delivery_id=?', (delivery_id,))
            if existing:
                if existing['artifact_id'] != artifact_id or existing['recipient'] != recipient or json.loads(existing['context']) != request:
                    reject('delivery_conflict', 'Delivery identifier already refers to other content')
                return self.get(delivery_id)
            exported = artifacts.export(self.store, artifact_id, request)
            payload = {'format': 'rights-delivery', 'version': 1, 'delivery_id': delivery_id, 'recipient': recipient, 'attestation': exported}
            sha = checksum(payload)
            self.store.execute("INSERT INTO deliveries(delivery_id,artifact_id,recipient,context,export_id,payload,digest,state,created_at) VALUES(?,?,?,?,?,?,?,'prepared',?)", (delivery_id, artifact_id, recipient, canonical(request), exported['export_id'], canonical(payload), sha, self.store.clock()))
            audit.append(self.store, 'delivery.prepared', {'delivery_id': delivery_id, 'recipient': recipient, 'sha256': sha})
            return self.get(delivery_id)

    def get(self, delivery_id):
        row = self.store.one('SELECT * FROM deliveries WHERE delivery_id=?', (delivery_id,))
        if row is None:
            reject('unknown_delivery', 'Delivery does not exist')
        row['payload'] = json.loads(row['payload'])
        row['context'] = json.loads(row['context'])
        row['acknowledgement'] = json.loads(row['acknowledgement']) if row['acknowledgement'] else None
        if checksum(row['payload']) != row['digest']:
            reject('delivery_corrupt', 'Stored delivery checksum mismatch')
        return row

    def acknowledge(self, delivery_id, recipient, expected_digest, receipt_id):
        name(receipt_id, 'receipt_id')
        with self.store.atomic():
            delivery = self.get(delivery_id)
            if delivery['recipient'] != recipient or delivery['digest'] != expected_digest:
                reject('delivery_ack_identity', 'Acknowledgement recipient or checksum mismatch')
            if delivery['state'] == 'withdrawn':
                reject('delivery_withdrawn', 'Withdrawn delivery cannot be acknowledged')
            acknowledgment = {'recipient': recipient, 'receipt_id': receipt_id, 'digest': expected_digest}
            if delivery['acknowledgement']:
                if delivery['acknowledgement'] != acknowledgment:
                    reject('delivery_ack_conflict', 'Delivery has a different receipt')
                return delivery
            decision = artifacts.verify(self.store, delivery['artifact_id'], delivery['context'])
            if not decision['valid']:
                reject('delivery_invalid', 'Delivery authorization changed before receipt', failures=decision['failures'])
            self.store.execute("UPDATE deliveries SET state='acknowledged',acknowledgement=?,acknowledged_at=? WHERE delivery_id=?", (canonical(acknowledgment), self.store.clock(), delivery_id))
            audit.append(self.store, 'delivery.acknowledged', {'delivery_id': delivery_id, 'receipt_id': receipt_id})
            return self.get(delivery_id)

    def reconcile(self, at):
        at = timestamp(at)
        created = []
        with self.store.atomic():
            rows = self.store.all("SELECT delivery_id FROM deliveries WHERE state!='withdrawn' ORDER BY delivery_id")
            for row in rows:
                delivery = self.get(row['delivery_id'])
                context = {**delivery['context'], 'at': at}
                decision = artifacts.verify(self.store, delivery['artifact_id'], context)
                if decision['valid']:
                    continue
                payload = {'delivery_id': row['delivery_id'], 'recipient': delivery['recipient'], 'failures': decision['failures'], 'original_digest': delivery['digest'], 'receipt_existed': delivery['acknowledgement'] is not None}
                alert_id = 'alert-' + checksum(payload)
                self.store.execute('INSERT OR IGNORE INTO delivery_alerts(alert_id,delivery_id,reason,payload,created_at) VALUES(?,?,?,?,?)', (alert_id, row['delivery_id'], 'authorization_invalidated', canonical(payload), self.store.clock()))
                self.store.execute("UPDATE deliveries SET state='withdrawn' WHERE delivery_id=?", (row['delivery_id'],))
                created.append(alert_id)
            if created:
                audit.append(self.store, 'delivery.reconciled', {'alerts': created, 'at': at})
        return {'alerts': created, 'count': len(created)}

    def alerts(self, recipient=None, pending_only=True):
        if type(pending_only) is not bool:
            reject('delivery_filter', 'pending_only must be boolean')
        clauses = []
        params = []
        if recipient is not None:
            clauses.append('d.recipient=?')
            params.append(name(recipient, 'recipient'))
        if pending_only:
            clauses.append('a.acknowledged_at IS NULL')
        query = 'SELECT a.* FROM delivery_alerts a JOIN deliveries d ON d.delivery_id=a.delivery_id'
        if clauses:
            query += ' WHERE ' + ' AND '.join(clauses)
        query += ' ORDER BY a.created_at,a.alert_id'
        rows = self.store.all(query, params)
        for row in rows:
            row['payload'] = json.loads(row['payload'])
        return rows

    def acknowledge_alert(self, alert_id, recipient):
        with self.store.atomic():
            row = self.store.one('SELECT a.*,d.recipient FROM delivery_alerts a JOIN deliveries d ON d.delivery_id=a.delivery_id WHERE a.alert_id=?', (alert_id,))
            if row is None or row['recipient'] != recipient:
                reject('alert_recipient', 'Alert is not available to that recipient')
            if row['acknowledged_at'] is None:
                self.store.execute('UPDATE delivery_alerts SET acknowledged_at=? WHERE alert_id=?', (self.store.clock(), alert_id))
                audit.append(self.store, 'delivery.alert_acknowledged', {'alert_id': alert_id, 'recipient': recipient})
            return {'alert_id': alert_id, 'acknowledged': True}

    def listing(self, recipient=None):
        query = 'SELECT delivery_id FROM deliveries'
        params = ()
        if recipient:
            query += ' WHERE recipient=?'
            params = (name(recipient, 'recipient'),)
        query += ' ORDER BY delivery_id'
        return [self.get(row['delivery_id']) for row in self.store.all(query, params)]


def inspect_envelope(value, recipient):
    fields(value, {'payload', 'sha256'})
    if checksum(value['payload']) != value['sha256']:
        reject('delivery_digest', 'Delivery envelope checksum mismatch')
    payload = value['payload']
    fields(payload, {'format', 'version', 'delivery_id', 'recipient', 'attestation'})
    if payload['format'] != 'rights-delivery' or payload['version'] != 1:
        reject('delivery_format', 'Unsupported delivery format')
    if payload['recipient'] != recipient:
        reject('delivery_recipient', 'Delivery is addressed to another recipient')
    proof = artifacts.verify_export(payload['attestation'])
    return {'delivery_id': payload['delivery_id'], 'recipient': recipient, 'integrity': proof['integrity'], 'declared_context_allowed': proof['declared_context_allowed'], 'live_revocation_checked': False}
