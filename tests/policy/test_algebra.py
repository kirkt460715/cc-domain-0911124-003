from tests.support import Case, column, policy, context
from rights_graph.policy import algebra, grants, analysis, portfolios
from rights_graph.catalog import assets
from rights_graph.planner import plans, artifacts, invalidation


class PolicyTests(Case):
    def test_intersection_narrows_and_unions_obligations(self):
        left = algebra.normalize(policy())
        right = algebra.normalize(policy(purposes=['research'], regions=['cn'], rights=['read'], obligations=['consent'], max_depth=2))
        merged = algebra.intersect([left, right])
        self.assertEqual(merged['purposes'], ['research'])
        self.assertEqual(merged['regions'], ['cn'])
        self.assertEqual(merged['rights'], ['read'])
        self.assertEqual(merged['obligations'], ['attribution', 'consent'])
        self.assertEqual(merged['max_depth'], 2)
        self.assertTrue(merged['usable'])
        self.assertNotIn('columns', merged)
        self.assertEqual(left['max_depth'], 10)

    def test_half_open_interval(self):
        normalized = algebra.normalize(policy())
        start = algebra.evaluate(normalized, context(at='2026-01-01T00:00:00Z'))
        end = algebra.evaluate(normalized, context(at='2027-01-01T00:00:00Z'))
        before = algebra.evaluate(normalized, context(at='2025-12-31T23:59:59Z'))
        self.assertTrue(start['allowed'])
        self.assertFalse(end['allowed'])
        self.assertFalse(before['allowed'])
        self.assertEqual(end['reasons'][0]['code'], 'expired')
        self.assertEqual(before['reasons'][0]['code'], 'not_yet_valid')
        self.assertEqual(start['context']['at'], '2026-01-01T00:00:00.000000Z')

    def test_multiple_denials_reported(self):
        normalized = algebra.normalize(policy(max_depth=0, allow_derivatives=False))
        result = algebra.evaluate(normalized, context(purpose='sales', region='us', right='train', fulfilled_obligations=[]), depth=1)
        codes = {reason['code'] for reason in result['reasons']}
        self.assertFalse(result['allowed'])
        self.assertIn('purpose_denied', codes)
        self.assertIn('region_denied', codes)
        self.assertIn('right_denied', codes)
        self.assertIn('obligations_unfulfilled', codes)
        self.assertIn('derivation_depth', codes)
        self.assertIn('derivatives_denied', codes)

    def test_empty_intersection(self):
        left = algebra.normalize(policy(regions=['cn']))
        right = algebra.normalize(policy(regions=['eu']))
        result = algebra.intersect([left, right])
        self.assertFalse(result['usable'])
        self.assertEqual(result['regions'], [])
        self.assertEqual(result['purposes'], ['research', 'search'])
        self.assertEqual(result['obligations'], ['attribution'])
        self.fails('policy_empty', algebra.intersect, [])
        self.fails('policy_interval', algebra.normalize, policy(valid_until='2026-01-01T00:00:00Z'))

    def test_policy_validation(self):
        self.fails('policy_right', algebra.normalize, policy(rights=['sell']))
        self.fails('policy_derivatives', algebra.normalize, policy(allow_derivatives=1))
        from rights_graph.primitives import GraphError
        with self.assertRaises(GraphError):
            algebra.normalize(policy(max_depth=True))
        with self.assertRaises(GraphError):
            algebra.normalize(policy(columns=['text', 'text']))
        self.fails('context_right', algebra.context, context(right='sell'))
        self.fails('context_classification', algebra.context, context(maximum_classification='secret'))
        self.assertEqual(algebra.normalize(policy(max_depth=0))['max_depth'], 0)

    def test_grant_revision_preserves_history(self):
        self.source()
        original = grants.get(self.store, 'grant-source')
        changed = grants.revise(self.store, 'grant-source', 1, policy(regions=['cn']), 'Regional restriction')
        self.assertEqual(changed['revision'], 2)
        self.assertEqual(changed['policy']['regions'], ['cn'])
        self.assertEqual(grants.get(self.store, 'grant-source', 1)['policy']['regions'], ['cn', 'eu'])
        self.assertEqual(len(grants.history(self.store, 'grant-source')), 2)
        self.fails('stale_grant', grants.revise, self.store, 'grant-source', 1, policy(), 'Stale edit')
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 2)
        self.assertEqual(original['revision'], 1)

    def test_revocation_is_terminal(self):
        self.source()
        revoked = grants.revoke(self.store, 'grant-source', 1, 'Withdrawal')
        self.assertEqual(revoked['state'], 'revoked')
        self.assertEqual(revoked['revision'], 2)
        self.fails('grant_terminal', grants.revise, self.store, 'grant-source', 2, policy(), 'Reactivation')
        repeated = grants.revoke(self.store, 'grant-source', 2, 'Same withdrawal')
        self.assertEqual(repeated['revision'], 2)
        self.assertEqual(grants.for_asset(self.store, 'source'), [])
        self.assertEqual(len(grants.for_asset(self.store, 'source', False)), 1)
        self.assertEqual(len(grants.history(self.store, 'grant-source')), 2)

    def test_source_only_and_column_scoped(self):
        self.source()
        self.derived()
        self.fails('grant_asset', grants.create, self.store, 'derived-grant', 'derived', policy())
        self.fails('grant_columns', grants.create, self.store, 'unknown-column', 'source', policy(['missing']))
        self.fails('grant_exists', grants.create, self.store, 'grant-source', 'source', policy())
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM grants'), 1)
        assets.retire(self.store, 'source', 1, 'Closed')
        self.fails('grant_asset', grants.create, self.store, 'retired-grant', 'source', policy())
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM grants'), 1)

    def test_revoke_propagates_to_all_descendants(self):
        self.chain()
        plan, artifact = self.build('final')
        before = analysis.revocation_impact(self.store, 'grant-source')
        self.assertTrue(artifacts.verify(self.store, artifact)['valid'])
        grants.revoke(self.store, 'grant-source', 1, 'Consent withdrawn')
        self.assertFalse(artifacts.verify(self.store, artifact)['valid'])
        self.assertFalse(plans.freshness(self.store, plan['plan_id'])['fresh'])
        self.assertEqual(len(artifacts.listing(self.store, status='invalid')), 3)
        self.assertEqual(len(invalidation.history(self.store)), 3)
        self.assertTrue(before)

    def test_revision_invalidates_even_if_widening(self):
        self.source()
        self.derived()
        plan, artifact = self.build()
        grants.revise(self.store, 'grant-source', 1, policy(regions=['cn', 'eu', 'us']), 'Expanded')
        self.assertFalse(artifacts.verify(self.store, artifact)['valid'])
        self.assertFalse(plans.freshness(self.store, plan['plan_id'])['fresh'])
        revised = plans.create(self.store, 'derived', context())
        self.assertNotEqual(revised['plan_id'], plan['plan_id'])
        self.assertTrue(plans.freshness(self.store, revised['plan_id'])['fresh'])
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 2)

    def test_individual_grants_are_not_union_authorization(self):
        self.source(columns=[column('left'), column('right')], grant_policy=policy(['left']))
        grants.create(self.store, 'grant-right', 'source', policy(['right']))
        result = portfolios.minimal_columns(self.store, 'source', context())
        self.assertEqual([row['column'] for row in result['authorized_individually']], ['left', 'right'])
        self.assertEqual(result['denied'], [])
        self.assertFalse(result['union_is_authorized'])
        self.assertIsNone(result['combined_policy'])
        self.assertIsNotNone(result['combined_failure'])
        self.fails('authorization_denied', plans.create, self.store, 'source', context())

    def test_portfolio_context_comparison(self):
        self.source()
        self.derived()
        result = portfolios.assess(self.store, ['source', 'derived'], [context(), context(region='us')])
        self.assertEqual(len(result['results']), 4)
        self.assertEqual(result['coverage'][0]['allowed'], 2)
        self.assertEqual(result['coverage'][1]['allowed'], 0)
        compared = portfolios.compare_contexts(self.store, 'derived', context(), context(region='us'))
        self.assertEqual(compared['lost_columns'], ['text'])
        self.assertEqual(compared['gained_columns'], [])
        self.assertTrue(compared['before_union_authorized'])
        self.assertFalse(compared['after_union_authorized'])

    def test_obligation_inventory_not_authorization(self):
        self.source()
        self.derived()
        grants.create(self.store, 'other', 'source', policy(obligations=['consent']))
        result = portfolios.obligation_inventory(self.store, 'derived')
        self.assertEqual([row['obligation'] for row in result['obligations']], ['attribution', 'consent'])
        self.assertEqual(result['obligations'][0]['assets'], ['source'])
        self.assertEqual(result['obligations'][1]['grants'], ['other'])
        self.assertIn('not_an_authorization', result['semantics'])
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM plans'), 0)
