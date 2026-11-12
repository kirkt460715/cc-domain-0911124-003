from tests.support import Case, context, policy, column
from rights_graph.catalog import assets
from rights_graph.policy import grants
from rights_graph.planner import artifacts
from rights_graph.planner.delivery import inspect_envelope


class WorkflowTests(Case):
    def prepare(self):
        self.source()
        self.derived()
        return self.build()

    def test_proposal_simulation_rolls_back(self):
        plan, artifact = self.prepare()
        count_before = self.store.scalar('SELECT COUNT(*) FROM audit')
        analysis = self.app.proposals.analyze('grant-source', policy(regions=['eu']))
        self.assertFalse(analysis['recompilation'][0]['allowed'])
        self.assertEqual(analysis['changes']['removed']['regions'], ['cn'])
        self.assertEqual(grants.get(self.store, 'grant-source')['policy']['regions'], ['cn', 'eu'])
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 1)
        self.assertTrue(artifacts.verify(self.store, artifact)['valid'])
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM audit'), count_before)
        self.assertEqual(len(analysis['live_artifacts']), 2)

    def test_proposal_requires_independent_reviewer(self):
        self.prepare()
        desk = self.app.proposals
        proposal = desk.submit('change', 'grant-source', policy(regions=['cn']), 'alice', 'Limit region')
        self.fails('proposal_separation', desk.review, 'change', 'alice', True, 'Approve', proposal['analysis_hash'])
        self.fails('proposal_analysis', desk.review, 'change', 'bob', True, 'Approve', 'wrong')
        self.assertEqual(desk.get('change')['state'], 'pending')
        reviewed = desk.review('change', 'bob', True, 'Reviewed', proposal['analysis_hash'])
        self.assertEqual(reviewed['state'], 'applied')
        self.assertEqual(reviewed['reviewer'], 'bob')
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 2)
        self.assertEqual(grants.get(self.store, 'grant-source')['policy']['regions'], ['cn'])
        self.fails('proposal_terminal', desk.review, 'change', 'carol', True, 'Again', proposal['analysis_hash'])

    def test_stale_proposal_needs_refresh(self):
        self.prepare()
        desk = self.app.proposals
        original = desk.submit('change', 'grant-source', policy(regions=['cn']), 'alice', 'Limit region')
        assets.revise(self.store, 'source', 1, [column()], 'New content')
        self.fails('proposal_stale', desk.review, 'change', 'bob', True, 'Approve', original['analysis_hash'])
        self.fails('proposal_refresh', desk.refresh, 'change', 'bob')
        refreshed = desk.refresh('change', 'alice')
        self.assertNotEqual(refreshed['analysis_hash'], original['analysis_hash'])
        self.assertEqual(refreshed['state'], 'pending')
        applied = desk.review('change', 'bob', True, 'Updated review', refreshed['analysis_hash'])
        self.assertEqual(applied['state'], 'applied')
        self.assertEqual(len(desk.listing('applied')), 1)

    def test_rejected_proposal_does_not_change_grant(self):
        self.prepare()
        desk = self.app.proposals
        proposal = desk.submit('change', 'grant-source', policy(regions=['eu']), 'alice', 'Region request')
        result = desk.review('change', 'bob', False, 'Would break consumers', proposal['analysis_hash'])
        self.assertEqual(result['state'], 'rejected')
        self.assertEqual(result['decision_reason'], 'Would break consumers')
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 1)
        self.assertEqual(len(desk.listing('rejected')), 1)
        self.assertEqual(desk.listing('pending'), [])
        self.fails('proposal_refresh', desk.refresh, 'change', 'alice')
        self.fails('proposal_exists', desk.submit, 'change', 'grant-source', policy(), 'alice', 'Again')

    def test_campaign_collects_partial_failures(self):
        self.prepare()
        campaign = self.app.campaigns
        requests = [{'target': 'derived', 'context': context()}, {'target': 'source', 'context': context(region='us')}]
        created = campaign.create('release', requests)
        self.assertEqual(len(created['members']), 2)
        self.assertTrue(campaign.advance('release')['advanced'])
        second = campaign.advance('release')['campaign']
        self.assertEqual([row['state'] for row in second['members']], ['complete', 'failed'])
        self.assertEqual(second['members'][1]['failure']['code'], 'authorization_denied')
        self.fails('campaign_failures', campaign.close, 'release')
        self.assertEqual(campaign.close('release', True)['state'], 'partial')
        self.assertEqual(campaign.report('release')['complete_count'], 1)
        self.fails('campaign_closed', campaign.advance, 'release')

    def test_campaign_retry_after_authorization_change(self):
        self.source()
        campaign = self.app.campaigns
        campaign.create('release', [{'target': 'source', 'context': context(region='us')}])
        campaign.advance('release')
        self.assertEqual(campaign.report('release')['complete_count'], 0)
        grants.revise(self.store, 'grant-source', 1, policy(regions=['cn', 'us']), 'New region')
        self.assertEqual(campaign.retry('release', 0)['members'][0]['state'], 'pending')
        campaign.advance('release')
        self.assertEqual(campaign.close('release')['state'], 'complete')
        report = campaign.report('release')
        self.assertEqual(report['complete_count'], 1)
        self.assertTrue(report['members'][0]['current_authorization']['valid'])
        self.assertEqual(campaign.close('release')['state'], 'complete')

    def test_campaign_close_rechecks_revocation(self):
        self.source()
        campaign = self.app.campaigns
        campaign.create('release', [{'target': 'source', 'context': context()}])
        self.fails('campaign_pending', campaign.close, 'release')
        campaign.advance('release')
        self.assertEqual(campaign.get('release')['members'][0]['state'], 'complete')
        grants.revoke(self.store, 'grant-source', 1, 'Withdraw')
        self.fails('campaign_stale', campaign.close, 'release')
        self.assertEqual(campaign.get('release')['state'], 'open')
        self.assertFalse(campaign.report('release')['members'][0]['current_authorization']['valid'])
        self.assertFalse(campaign.advance('release')['advanced'])

    def test_campaign_idempotence_and_retry_guards(self):
        self.source()
        campaign = self.app.campaigns
        requests = [{'target': 'source', 'context': context()}]
        first = campaign.create('release', requests)
        second = campaign.create('release', requests)
        self.assertEqual(first['digest'], second['digest'])
        self.assertEqual(len(second['members']), 1)
        self.fails('campaign_conflict', campaign.create, 'release', [{'target': 'source', 'context': context(region='eu')}])
        self.fails('campaign_retry', campaign.retry, 'release', 0)
        self.fails('campaign_ordinal', campaign.retry, 'release', 1)
        self.assertEqual(campaign.get('release')['state'], 'open')
        self.assertEqual(campaign.get('release')['members'][0]['state'], 'pending')

    def test_delivery_requires_distribution_and_recipient(self):
        plan, artifact = self.prepare()
        desk = self.app.deliveries
        self.fails('delivery_right', desk.prepare, 'delivery', artifact, 'reader', context())
        item = desk.prepare('delivery', artifact, 'reader', context(right='distribute'))
        self.assertEqual(item['state'], 'prepared')
        self.assertEqual(item['recipient'], 'reader')
        checked = inspect_envelope({'payload': item['payload'], 'sha256': item['digest']}, 'reader')
        self.assertTrue(checked['integrity'])
        self.assertFalse(checked['live_revocation_checked'])
        self.fails('delivery_recipient', inspect_envelope, {'payload': item['payload'], 'sha256': item['digest']}, 'other')
        self.assertEqual(len(desk.listing('reader')), 1)

    def test_delivery_ack_is_identity_bound_and_idempotent(self):
        plan, artifact = self.prepare()
        desk = self.app.deliveries
        item = desk.prepare('delivery', artifact, 'reader', context(right='distribute'))
        self.fails('delivery_ack_identity', desk.acknowledge, 'delivery', 'other', item['digest'], 'receipt')
        self.fails('delivery_ack_identity', desk.acknowledge, 'delivery', 'reader', 'bad', 'receipt')
        result = desk.acknowledge('delivery', 'reader', item['digest'], 'receipt')
        self.assertEqual(result['state'], 'acknowledged')
        self.assertEqual(result['acknowledgement']['receipt_id'], 'receipt')
        self.assertEqual(desk.acknowledge('delivery', 'reader', item['digest'], 'receipt'), result)
        self.fails('delivery_ack_conflict', desk.acknowledge, 'delivery', 'reader', item['digest'], 'other-receipt')
        self.assertEqual(desk.get('delivery')['digest'], item['digest'])

    def test_delivery_revocation_generates_durable_alert(self):
        plan, artifact = self.prepare()
        desk = self.app.deliveries
        item = desk.prepare('delivery', artifact, 'reader', context(right='distribute'))
        desk.acknowledge('delivery', 'reader', item['digest'], 'receipt')
        grants.revoke(self.store, 'grant-source', 1, 'Withdraw')
        reconciled = desk.reconcile('2026-11-12T00:00:00Z')
        self.assertEqual(reconciled['count'], 1)
        self.assertEqual(desk.get('delivery')['state'], 'withdrawn')
        alert = desk.alerts('reader')[0]
        self.assertTrue(alert['payload']['receipt_existed'])
        self.assertEqual(alert['payload']['original_digest'], item['digest'])
        self.assertEqual(desk.reconcile('2026-11-12T00:00:00Z')['count'], 0)
        self.fails('alert_recipient', desk.acknowledge_alert, alert['alert_id'], 'other')
        self.assertTrue(desk.acknowledge_alert(alert['alert_id'], 'reader')['acknowledged'])
        self.assertEqual(desk.alerts('reader'), [])
        self.assertEqual(len(desk.alerts('reader', False)), 1)

    def test_delivery_rechecks_before_receipt(self):
        plan, artifact = self.prepare()
        desk = self.app.deliveries
        item = desk.prepare('delivery', artifact, 'reader', context(right='distribute'))
        grants.revise(self.store, 'grant-source', 1, policy(rights=['read', 'transform']), 'Remove distribution')
        self.fails('delivery_invalid', desk.acknowledge, 'delivery', 'reader', item['digest'], 'receipt')
        self.assertEqual(desk.get('delivery')['state'], 'prepared')
        self.assertIsNone(desk.get('delivery')['acknowledgement'])
        desk.reconcile('2026-11-11T00:00:00Z')
        self.fails('delivery_withdrawn', desk.acknowledge, 'delivery', 'reader', item['digest'], 'receipt')
        self.assertEqual(desk.alerts()[0]['reason'], 'authorization_invalidated')
        self.assertFalse(desk.alerts()[0]['payload']['receipt_existed'])
