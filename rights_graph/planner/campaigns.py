import json
from rights_graph.primitives import canonical, checksum, fields, name, reject
from rights_graph.planner import plans, builds, artifacts
from rights_graph.journal import audit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS campaigns(
 campaign_id TEXT PRIMARY KEY,definition TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,
 created_at TEXT NOT NULL,closed_at TEXT);
CREATE TABLE IF NOT EXISTS campaign_members(
 campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),ordinal INTEGER NOT NULL,
 target TEXT NOT NULL,plan_id TEXT,build_id TEXT,state TEXT NOT NULL,failure TEXT,
 PRIMARY KEY(campaign_id,ordinal));
'''


class Campaigns:
    def __init__(self, store):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize campaigns outside transaction')
        store.db.executescript(SCHEMA)

    def create(self, campaign_id, requests):
        name(campaign_id, 'campaign_id')
        if not isinstance(requests, list) or not 1 <= len(requests) <= 100:
            reject('campaign_requests', 'Campaign requires one to one hundred target requests')
        normalized = []
        from rights_graph.policy.algebra import context
        for request in requests:
            fields(request, {'target', 'context'}, {'columns', 'grant_overrides'})
            target = name(request['target'], 'target')
            normalized.append({**request, 'target': target, 'context': context(request['context'])})
        digest = checksum(normalized)
        with self.store.atomic():
            existing = self.store.one('SELECT digest FROM campaigns WHERE campaign_id=?', (campaign_id,))
            if existing:
                if digest != existing['digest']:
                    reject('campaign_conflict', 'Campaign ID already uses other requests')
                return self.get(campaign_id)
            self.store.execute("INSERT INTO campaigns(campaign_id,definition,digest,state,created_at) VALUES(?,?,?,'open',?)", (campaign_id, canonical(normalized), digest, self.store.clock()))
            for ordinal, request in enumerate(normalized):
                self.store.execute("INSERT INTO campaign_members(campaign_id,ordinal,target,state) VALUES(?,?,?,'pending')", (campaign_id, ordinal, request['target']))
            audit.append(self.store, 'campaign.created', {'campaign_id': campaign_id, 'members': len(normalized)})
            return self.get(campaign_id)

    def get(self, campaign_id):
        row = self.store.one('SELECT * FROM campaigns WHERE campaign_id=?', (campaign_id,))
        if row is None:
            reject('unknown_campaign', 'Campaign does not exist')
        row['definition'] = json.loads(row['definition'])
        if checksum(row['definition']) != row['digest']:
            reject('campaign_corrupt', 'Campaign definition checksum mismatch')
        row['members'] = self.store.all('SELECT * FROM campaign_members WHERE campaign_id=? ORDER BY ordinal', (campaign_id,))
        for member in row['members']:
            member['failure'] = json.loads(member['failure']) if member['failure'] else None
        return row

    def advance(self, campaign_id, owner='campaign-worker'):
        from rights_graph.primitives import GraphError
        with self.store.atomic():
            campaign = self.get(campaign_id)
            if campaign['state'] != 'open':
                reject('campaign_closed', 'Campaign is already closed')
            candidates = [row for row in campaign['members'] if row['state'] == 'pending']
            if not candidates:
                return {'advanced': False, 'campaign': campaign}
            member = candidates[0]
            ordinal = member['ordinal']
            request = campaign['definition'][ordinal]
            try:
                with self.store.atomic():
                    plan = plans.create(self.store, request['target'], request['context'], columns=request.get('columns'), grant_overrides=request.get('grant_overrides'))
                    build_id = 'campaign-' + checksum({'campaign_id': campaign_id, 'ordinal': ordinal, 'plan_id': plan['plan_id']})
                    builds.create(self.store, build_id, plan['plan_id'])
                    build = builds.execute(self.store, build_id, owner)
                    self.store.execute("UPDATE campaign_members SET plan_id=?,build_id=?,state='complete',failure=NULL WHERE campaign_id=? AND ordinal=?", (plan['plan_id'], build_id, campaign_id, ordinal))
            except GraphError as exc:
                self.store.execute("UPDATE campaign_members SET state='failed',failure=? WHERE campaign_id=? AND ordinal=?", (canonical(exc.json()), campaign_id, ordinal))
            audit.append(self.store, 'campaign.advanced', {'campaign_id': campaign_id, 'ordinal': ordinal})
            return {'advanced': True, 'campaign': self.get(campaign_id)}

    def retry(self, campaign_id, ordinal):
        with self.store.atomic():
            campaign = self.get(campaign_id)
            if campaign['state'] != 'open':
                reject('campaign_closed', 'Cannot retry closed campaign')
            if type(ordinal) is not int or not 0 <= ordinal < len(campaign['members']):
                reject('campaign_ordinal', 'Campaign member index is invalid')
            member = campaign['members'][ordinal]
            if member['state'] != 'failed':
                reject('campaign_retry', 'Only failed members may be retried')
            self.store.execute("UPDATE campaign_members SET state='pending',failure=NULL WHERE campaign_id=? AND ordinal=?", (campaign_id, ordinal))
            audit.append(self.store, 'campaign.retry', {'campaign_id': campaign_id, 'ordinal': ordinal})
            return self.get(campaign_id)

    def close(self, campaign_id, allow_partial=False):
        if type(allow_partial) is not bool:
            reject('campaign_partial', 'allow_partial must be boolean')
        with self.store.atomic():
            campaign = self.get(campaign_id)
            if campaign['state'] != 'open':
                return campaign
            if any(row['state'] == 'pending' for row in campaign['members']):
                reject('campaign_pending', 'Pending members must be processed before closing')
            failures = [row for row in campaign['members'] if row['state'] == 'failed']
            if failures and not allow_partial:
                reject('campaign_failures', 'Failed members require explicit partial-close acknowledgement')
            for member in campaign['members']:
                if member['state'] == 'complete':
                    build = builds.get(self.store, member['build_id'])
                    proof = artifacts.verify(self.store, build['result']['target_artifact'])
                    if not proof['valid']:
                        reject('campaign_stale', 'Completed member no longer has valid authorization', ordinal=member['ordinal'])
            state = 'partial' if failures else 'complete'
            self.store.execute('UPDATE campaigns SET state=?,closed_at=? WHERE campaign_id=?', (state, self.store.clock(), campaign_id))
            audit.append(self.store, 'campaign.closed', {'campaign_id': campaign_id, 'state': state})
            return self.get(campaign_id)

    def report(self, campaign_id):
        campaign = self.get(campaign_id)
        members = []
        for row in campaign['members']:
            item = {'ordinal': row['ordinal'], 'target': row['target'], 'state': row['state'], 'failure': row['failure']}
            if row['build_id']:
                build = builds.get(self.store, row['build_id'])
                item['artifact_id'] = build['result']['target_artifact']
                item['current_authorization'] = artifacts.verify(self.store, item['artifact_id'])
            members.append(item)
        return {'campaign_id': campaign_id, 'state': campaign['state'], 'members': members, 'complete_count': sum(row['state'] == 'complete' for row in members)}
