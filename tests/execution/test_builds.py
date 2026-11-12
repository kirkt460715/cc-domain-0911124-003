from tests.support import Case, column, context, policy
from rights_graph.catalog import assets
from rights_graph.policy import grants
from rights_graph.planner import plans, builds, artifacts, recovery, inspection


class BuildTests(Case):
    def prepare(self):
        self.chain()
        plan = plans.create(self.store, 'final', context())
        builds.create(self.store, 'job', plan['plan_id'])
        return plan

    def test_artifacts_only_appear_on_finalize(self):
        self.prepare()
        token = builds.claim(self.store, 'job', 'one')
        first = builds.run_step(self.store, 'job', token)
        self.assertFalse(first['finished'])
        self.assertEqual(artifacts.listing(self.store), [])
        self.assertEqual(builds.get(self.store, 'job')['cursor'], 1)
        self.fails('build_incomplete', builds.finalize, self.store, 'job', token)
        builds.run_step(self.store, 'job', token)
        builds.run_step(self.store, 'job', token)
        finished = builds.finalize(self.store, 'job', token)
        self.assertEqual(finished['state'], 'complete')
        self.assertEqual(len(artifacts.listing(self.store)), 3)
        self.assertTrue(inspection.check(self.store)['ok'])

    def test_expired_worker_is_fenced(self):
        self.prepare()
        old = builds.claim(self.store, 'job', 'one', 1)
        builds.run_step(self.store, 'job', old)
        self.fails('build_busy', builds.claim, self.store, 'job', 'two')
        self.time = '2026-11-11T00:00:02.000000Z'
        new = builds.claim(self.store, 'job', 'two')
        self.assertEqual(new['generation'], 2)
        self.fails('build_fenced', builds.run_step, self.store, 'job', old)
        self.assertEqual(builds.get(self.store, 'job')['cursor'], 1)
        builds.run_step(self.store, 'job', new)
        builds.run_step(self.store, 'job', new)
        self.assertEqual(builds.finalize(self.store, 'job', new)['state'], 'complete')
        self.assertEqual(len(artifacts.listing(self.store)), 3)

    def test_recovery_resumes_verified_prefix(self):
        self.prepare()
        token = builds.claim(self.store, 'job', 'one', 1)
        first = builds.run_step(self.store, 'job', token)
        self.assertFalse(recovery.checkpoint(self.store, 'job')['resumable'])
        self.time = '2026-11-11T00:00:02.000000Z'
        checkpoint = recovery.checkpoint(self.store, 'job')
        self.assertTrue(checkpoint['resumable'])
        self.assertEqual(checkpoint['verified'], [0])
        self.assertEqual(checkpoint['pending'], [1, 2])
        result = recovery.resume(self.store, 'job')
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(builds.steps(self.store, 'job')[0]['payload'], first['evidence'])
        self.assertEqual(recovery.queue(self.store)['resumable'], [])

    def test_corrupt_checkpoint_cannot_resume(self):
        self.prepare()
        token = builds.claim(self.store, 'job', 'one', 1)
        builds.run_step(self.store, 'job', token)
        self.store.execute("UPDATE build_steps SET digest='bad' WHERE build_id='job' AND step_index=0")
        self.time = '2026-11-11T00:00:02.000000Z'
        inspected = recovery.checkpoint(self.store, 'job')
        self.assertFalse(inspected['resumable'])
        self.assertEqual(inspected['problems'][0]['code'], 'step_digest')
        self.fails('recovery_unsafe', recovery.resume, self.store, 'job')
        self.assertEqual(len(recovery.queue(self.store)['blocked']), 1)
        self.assertEqual(artifacts.listing(self.store), [])
        self.assertFalse(inspection.check(self.store)['ok'])

    def test_change_between_steps_blocks_finalization(self):
        plan = self.prepare()
        token = builds.claim(self.store, 'job', 'one')
        for _ in range(3):
            builds.run_step(self.store, 'job', token)
        grants.revoke(self.store, 'grant-source', 1, 'Withdrawn')
        self.fails('stale_plan', builds.finalize, self.store, 'job', token)
        self.assertEqual(artifacts.listing(self.store), [])
        self.assertEqual(builds.get(self.store, 'job')['state'], 'running')
        self.assertEqual(builds.get(self.store, 'job')['cursor'], 3)
        self.assertFalse(plans.freshness(self.store, plan['plan_id'])['fresh'])
        self.assertTrue(inspection.check(self.store)['ok'])

    def test_cancel_preserves_evidence_but_publishes_nothing(self):
        self.prepare()
        token = builds.claim(self.store, 'job', 'one')
        builds.run_step(self.store, 'job', token)
        revision = builds.get(self.store, 'job')['revision']
        self.fails('stale_build', builds.cancel, self.store, 'job', revision - 1, 'Stop')
        cancelled = builds.cancel(self.store, 'job', revision, 'Stop')
        self.assertEqual(cancelled['state'], 'cancelled')
        self.assertEqual(cancelled['error']['reason'], 'Stop')
        self.assertEqual(builds.steps(self.store, 'job')[0]['state'], 'verified')
        self.assertEqual(artifacts.listing(self.store), [])
        self.fails('build_state', builds.run_step, self.store, 'job', token)
        self.fails('build_state', builds.claim, self.store, 'job', 'new')

    def test_idempotent_build_and_plan_identity(self):
        plan = self.prepare()
        same = plans.create(self.store, 'final', context())
        self.assertEqual(plan['plan_id'], same['plan_id'])
        self.assertEqual(builds.create(self.store, 'job', same['plan_id'])['state'], 'queued')
        result = builds.execute(self.store, 'job')
        again = builds.execute(self.store, 'job')
        self.assertEqual(result, again)
        self.assertEqual(len(artifacts.listing(self.store)), 3)
        other = plans.create(self.store, 'source', context())
        self.fails('build_conflict', builds.create, self.store, 'job', other['plan_id'])
        self.assertEqual(builds.get(self.store, 'job')['plan_id'], plan['plan_id'])

    def test_replan_uses_new_head(self):
        before = self.prepare()
        assets.revise(self.store, 'source', 1, [column()], 'Changed content')
        self.assertFalse(plans.freshness(self.store, before['plan_id'])['fresh'])
        result = recovery.replan(self.store, 'job', 'new-job')
        self.assertEqual(result['build']['state'], 'queued')
        self.assertNotEqual(result['build']['plan_id'], before['plan_id'])
        self.assertTrue(result['changes']['differences'])
        completed = builds.execute(self.store, 'new-job')
        self.assertEqual(completed['state'], 'complete')
        self.assertTrue(artifacts.verify(self.store, completed['result']['target_artifact'])['valid'])
        self.assertEqual(builds.get(self.store, 'job')['state'], 'queued')

    def test_heartbeat_and_expiration_boundary(self):
        self.prepare()
        token = builds.claim(self.store, 'job', 'worker', 1)
        renewed = builds.heartbeat(self.store, 'job', token, 10)
        self.assertGreater(renewed['expires_at'], token['expires_at'])
        self.time = '2026-11-11T00:00:02.000000Z'
        self.assertEqual(builds.run_step(self.store, 'job', token)['cursor'], 1)
        self.time = renewed['expires_at']
        self.fails('build_expired', builds.run_step, self.store, 'job', token)
        self.assertEqual(builds.get(self.store, 'job')['cursor'], 1)
        self.assertTrue(recovery.checkpoint(self.store, 'job')['resumable'])
        self.assertEqual(builds.claim(self.store, 'job', 'replacement')['generation'], 2)

    def test_artifact_export_is_integrity_not_live_signature(self):
        self.chain()
        plan, artifact = self.build('final')
        envelope = artifacts.export(self.store, artifact)
        checked = artifacts.verify_export(envelope)
        self.assertTrue(checked['integrity'])
        self.assertTrue(checked['declared_context_allowed'])
        self.assertFalse(checked['live_revocation_checked'])
        self.assertEqual(envelope['payload']['source_inputs'][0]['source_asset'], 'source')
        envelope['payload']['asset_id'] = 'tampered'
        self.fails('export_integrity', artifacts.verify_export, envelope)
        self.assertTrue(artifacts.verify(self.store, artifact)['valid'])

    def test_expiry_and_withdrawal(self):
        self.chain()
        plan, artifact = self.build('final')
        expired = artifacts.verify(self.store, artifact, context(at='2027-01-01T00:00:00Z'))
        self.assertFalse(expired['valid'])
        self.assertIn('expired', {item['code'] for item in expired['failures']})
        withdrawn = artifacts.withdraw(self.store, artifact, 'Review requested')
        self.assertEqual(withdrawn['artifact']['status'], 'invalid')
        self.assertFalse(artifacts.verify(self.store, artifact)['valid'])
        self.fails('artifact_unusable', artifacts.export, self.store, artifact)
        self.assertEqual(len(artifacts.listing(self.store, status='valid')), 2)
        self.assertTrue(inspection.check(self.store)['ok'])
