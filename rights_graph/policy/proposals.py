import json
from rights_graph.primitives import canonical, checksum, fields, label, name, reject
from rights_graph.policy import grants
from rights_graph.policy.algebra import normalize, narrowing
from rights_graph.planner import plans, artifacts
from rights_graph.journal import audit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS policy_proposals(
 proposal_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL,base_revision INTEGER NOT NULL,
 candidate TEXT NOT NULL,reason TEXT NOT NULL,author TEXT NOT NULL,state TEXT NOT NULL,
 analysis TEXT NOT NULL,analysis_hash TEXT NOT NULL,reviewer TEXT,decision_reason TEXT,
 created_at TEXT NOT NULL,decided_at TEXT);
'''


class ProposalDesk:
    def __init__(self, store):
        self.store = store
        if store.depth:
            reject('transaction_scope', 'Initialize proposal desk outside transaction')
        store.db.executescript(SCHEMA)

    def analyze(self, grant_id, candidate):
        candidate = normalize(candidate)
        original = grants.get(self.store, grant_id)
        if original['state'] != 'active':
            reject('grant_terminal', 'Only active grants may be proposed for change')
        artifact_rows = self.store.all(
            'SELECT DISTINCT artifact_id FROM artifact_inputs WHERE grant_id=? ORDER BY artifact_id', (grant_id,))
        before = []
        after = []
        for row in artifact_rows:
            artifact = artifacts.get(self.store, row['artifact_id'])
            if artifact['status'] != 'valid':
                continue
            before.append({'artifact_id': row['artifact_id'], 'verification': artifacts.verify(self.store, row['artifact_id'])})
        from rights_graph.planner.lineage import compile_graph
        candidates = []
        for plan in plans.listing(self.store):
            leaves = [leaf for step in plan['payload']['steps'] for roots in step['lineage'].values() for leaf in roots]
            if any(leaf['grant_id'] == grant_id for leaf in leaves):
                candidates.append(plan)
        self.store.execute('SAVEPOINT proposal_simulation')
        try:
            self.store.execute('UPDATE grants SET policy=? WHERE grant_id=?', (canonical(candidate), grant_id))
            for plan in candidates:
                selected = plan['payload']['steps'][-1]['columns']
                try:
                    compiled = compile_graph(self.store, plan['target'], plan['context'], selected)
                    after.append({'plan_id': plan['plan_id'], 'allowed': True, 'target_policy': compiled['result']['policy']})
                except Exception as exc:
                    from rights_graph.primitives import GraphError
                    if not isinstance(exc, GraphError):
                        raise
                    after.append({'plan_id': plan['plan_id'], 'allowed': False, 'failure': exc.json()})
        finally:
            self.store.execute('ROLLBACK TO proposal_simulation')
            self.store.execute('RELEASE proposal_simulation')
        return {
            'grant_id': grant_id,
            'base_revision': original['revision'],
            'candidate': candidate,
            'changes': narrowing(original['policy'], candidate),
            'live_artifacts': before,
            'recompilation': after,
            'catalog_fingerprint': self.fingerprint(),
        }

    def fingerprint(self):
        return checksum({
            'assets': self.store.all('SELECT asset_id,head,state FROM assets ORDER BY asset_id'),
            'recipes': self.store.all('SELECT recipe_id,revision,digest FROM recipes ORDER BY recipe_id'),
            'grants': self.store.all('SELECT grant_id,revision,state FROM grants ORDER BY grant_id'),
            'plans': self.store.all('SELECT plan_id,digest FROM plans ORDER BY plan_id'),
            'artifacts': self.store.all('SELECT artifact_id,status FROM artifacts ORDER BY artifact_id'),
        })

    def submit(self, proposal_id, grant_id, candidate, author, reason):
        name(proposal_id, 'proposal_id')
        name(author, 'author')
        reason = label(reason, 'reason')
        with self.store.atomic():
            if self.store.one('SELECT proposal_id FROM policy_proposals WHERE proposal_id=?', (proposal_id,)):
                reject('proposal_exists', 'Proposal identifier already exists')
            result = self.analyze(grant_id, candidate)
            self.store.execute(
                "INSERT INTO policy_proposals(proposal_id,grant_id,base_revision,candidate,reason,author,state,analysis,analysis_hash,created_at) VALUES(?,?,?,?,?,?,'pending',?,?,?)",
                (proposal_id, grant_id, result['base_revision'], canonical(result['candidate']), reason, author, canonical(result), checksum(result), self.store.clock()))
            audit.append(self.store, 'proposal.submitted', {'proposal_id': proposal_id, 'analysis_hash': checksum(result)})
            return self.get(proposal_id)

    def get(self, proposal_id):
        row = self.store.one('SELECT * FROM policy_proposals WHERE proposal_id=?', (proposal_id,))
        if row is None:
            reject('unknown_proposal', 'Policy proposal does not exist')
        row['candidate'] = json.loads(row['candidate'])
        row['analysis'] = json.loads(row['analysis'])
        if checksum(row['analysis']) != row['analysis_hash']:
            reject('proposal_corrupt', 'Proposal analysis checksum changed')
        return row

    def review(self, proposal_id, reviewer, accept, reason, expected_analysis_hash):
        name(reviewer, 'reviewer')
        reason = label(reason, 'reason')
        if type(accept) is not bool:
            reject('proposal_decision', 'Review decision must be boolean')
        with self.store.atomic():
            proposal = self.get(proposal_id)
            if proposal['state'] != 'pending':
                reject('proposal_terminal', 'Proposal has already been decided')
            if reviewer == proposal['author']:
                reject('proposal_separation', 'Author cannot approve their own change')
            if expected_analysis_hash != proposal['analysis_hash']:
                reject('proposal_analysis', 'Reviewer did not acknowledge current analysis')
            if accept:
                if self.fingerprint() != proposal['analysis']['catalog_fingerprint']:
                    reject('proposal_stale', 'Dependencies changed; refresh analysis before approving')
                grants.revise(self.store, proposal['grant_id'], proposal['base_revision'], proposal['candidate'], proposal['reason'])
            state = 'applied' if accept else 'rejected'
            self.store.execute('UPDATE policy_proposals SET state=?,reviewer=?,decision_reason=?,decided_at=? WHERE proposal_id=?', (state, reviewer, reason, self.store.clock(), proposal_id))
            audit.append(self.store, 'proposal.reviewed', {'proposal_id': proposal_id, 'state': state, 'reviewer': reviewer})
            return self.get(proposal_id)

    def refresh(self, proposal_id, author):
        with self.store.atomic():
            proposal = self.get(proposal_id)
            if proposal['author'] != author or proposal['state'] != 'pending':
                reject('proposal_refresh', 'Only author can refresh pending proposal')
            result = self.analyze(proposal['grant_id'], proposal['candidate'])
            self.store.execute('UPDATE policy_proposals SET base_revision=?,analysis=?,analysis_hash=? WHERE proposal_id=?', (result['base_revision'], canonical(result), checksum(result), proposal_id))
            audit.append(self.store, 'proposal.refreshed', {'proposal_id': proposal_id, 'analysis_hash': checksum(result)})
            return self.get(proposal_id)

    def listing(self, state=None):
        if state not in {None, 'pending', 'applied', 'rejected'}:
            reject('proposal_state', 'Unknown proposal state')
        query = 'SELECT proposal_id FROM policy_proposals'
        args = ()
        if state:
            query += ' WHERE state=?'
            args = (state,)
        query += ' ORDER BY created_at,proposal_id'
        return [self.get(row['proposal_id']) for row in self.store.all(query, args)]
