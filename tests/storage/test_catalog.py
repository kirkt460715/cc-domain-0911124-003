import copy
import json
import pathlib
import tempfile
from tests.support import Case, column, context, recipe, policy
from rights_graph.service import RightsService
from rights_graph.catalog import assets, importing, recipes
from rights_graph.journal import audit
from rights_graph.planner import inspection, recovery, plans
from rights_graph.primitives import checksum, json_loads, GraphError


class StorageTests(Case):
    def test_portable_catalog_roundtrip(self):
        self.chain()
        exported = importing.export_catalog(self.store)
        self.assertTrue(importing.verify_catalog_export(exported)['ok'])
        with RightsService() as target:
            imported = importing.import_catalog(target.store, exported['catalog'])
            self.assertEqual(imported['assets'], ['derived', 'final', 'source'])
            self.assertEqual(len(imported['recipes']), 2)
            copied = importing.export_catalog(target.store)
            self.assertEqual(copied['sha256'], exported['sha256'])
            self.assertEqual(importing.compare_catalogs(exported, copied)['count'], 0)
            self.assertTrue(inspection.check(target.store)['ok'])
            self.assertEqual(plans.create(target.store, 'final', context())['target'], 'final')

    def test_import_rolls_back_all_assets_on_failure(self):
        self.source()
        exported = importing.export_catalog(self.store)['catalog']
        exported['assets'][0]['asset_id'] = 'new'
        exported['grants'][0]['asset_id'] = 'missing'
        before = self.store.scalar('SELECT COUNT(*) FROM audit')
        self.fails('unknown_asset', importing.import_catalog, self.store, exported)
        self.assertEqual(len(assets.listing(self.store)), 1)
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM audit'), before)
        self.fails('unknown_asset', assets.get, self.store, 'new')
        self.assertTrue(self.store.integrity()['ok'])
        self.assertTrue(audit.verify(self.store)['ok'])

    def test_pinned_export_cannot_lose_history(self):
        self.source()
        definition = recipe()
        definition['inputs'][0]['version'] = 1
        self.derived(definition=definition)
        assets.revise(self.store, 'source', 1, [column()], 'New version')
        self.fails('catalog_pinned_export', importing.export_catalog, self.store)
        self.assertEqual(assets.get(self.store, 'source')['head'], 2)
        self.assertEqual(len(assets.versions(self.store, 'source')), 2)
        self.assertEqual(recipes.for_output(self.store, 'derived')['definition']['inputs'][0]['version'], 1)
        self.assertTrue(recovery.verify_history(self.store)['ok'])

    def test_nested_transaction_rollback(self):
        with self.store.atomic():
            self.source('outer')
            try:
                with self.store.atomic():
                    self.source('inner')
                    raise RuntimeError('rollback inner')
            except RuntimeError:
                pass
            self.assertEqual([row['asset_id'] for row in assets.listing(self.store)], ['outer'])
            self.assertEqual(self.store.depth, 1)
        self.assertEqual(self.store.depth, 0)
        self.assertEqual(len(assets.listing(self.store)), 1)
        self.assertTrue(audit.verify(self.store)['ok'])
        self.assertTrue(self.store.integrity()['ok'])

    def test_atomic_service_batch_rolls_back(self):
        requests = [{'operation': 'asset.create', 'arguments': {'asset_id': 'new', 'kind': 'source', 'owner': 'owner', 'columns': [column()], 'description': 'New'}}, {'operation': 'unknown', 'arguments': {}}]
        self.fails('unknown_operation', self.app.transaction, requests)
        self.assertEqual(assets.listing(self.store), [])
        self.assertEqual(audit.page(self.store), [])
        self.assertEqual(self.store.depth, 0)
        result = self.app.transaction(requests[:1])
        self.assertEqual(result[0]['asset_id'], 'new')
        self.assertEqual(len(assets.listing(self.store)), 1)
        self.assertTrue(self.app.dispatch('system.check', {})['ok'])

    def test_audit_hash_chain_detects_tampering(self):
        self.chain()
        rows = audit.page(self.store, limit=2)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['position'], 1)
        self.assertTrue(audit.verify(self.store)['ok'])
        remaining = audit.page(self.store, after=rows[-1]['position'])
        self.assertGreater(remaining[0]['position'], rows[-1]['position'])
        self.store.execute("UPDATE audit SET body='{}' WHERE position=2")
        checked = audit.verify(self.store)
        self.assertFalse(checked['ok'])
        self.assertEqual(checked['broken_at'], 2)
        self.assertFalse(inspection.check(self.store)['ok'])

    def test_plan_digest_and_dependency_index_checks(self):
        self.chain()
        plan = plans.create(self.store, 'final', context())
        self.assertTrue(inspection.check(self.store)['ok'])
        self.store.execute("DELETE FROM dependencies WHERE recipe_id='recipe-final'")
        report = inspection.check(self.store)
        self.assertFalse(report['ok'])
        self.assertIn('dependency_index', {row['code'] for row in report['problems']})
        self.store.execute('UPDATE plans SET payload=? WHERE plan_id=?', ('{}', plan['plan_id']))
        self.fails('plan_corrupt', plans.get, self.store, plan['plan_id'])
        self.assertIn('plan_digest', {row['code'] for row in inspection.check(self.store)['problems']})

    def test_disk_reopen_and_concurrent_optimistic_revision(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'graph.sqlite3'
            with RightsService(path) as first:
                assets.create(first.store, 'source', 'source', 'owner', [column()], 'Initial')
            with RightsService(path) as first, RightsService(path) as second:
                before = assets.get(second.store, 'source')
                assets.revise(first.store, 'source', 1, [column()], 'Second')
                self.assertEqual(before['head'], 1)
                self.fails('stale_head', assets.revise, second.store, 'source', 1, [column()], 'Conflicting')
                self.assertEqual(assets.get(second.store, 'source')['description'], 'Second')
                self.assertEqual(len(assets.versions(second.store, 'source')), 2)
                self.assertTrue(second.store.integrity()['ok'])
                self.assertTrue(audit.verify(second.store)['ok'])

    def test_json_rejects_duplicate_keys_and_nonfinite(self):
        with self.assertRaises(GraphError):
            json_loads('{"asset":"one","asset":"two"}')
        with self.assertRaises(GraphError):
            json_loads('{"n":NaN}')
        with self.assertRaises(GraphError):
            json_loads('{bad')
        self.assertEqual(json_loads('{"n":1}'), {'n': 1})
        self.assertEqual(checksum({'b': 2, 'a': 1}), checksum({'a': 1, 'b': 2}))
        self.assertNotEqual(checksum({'n': 1}), checksum({'n': '1'}))
        self.assertEqual(len(checksum({})), 64)

    def test_history_gap_is_detected(self):
        self.source()
        from rights_graph.policy import grants
        grants.revise(self.store, 'grant-source', 1, policy(regions=['cn']), 'Changed')
        self.assertTrue(recovery.verify_history(self.store)['ok'])
        self.store.execute("DELETE FROM grant_versions WHERE grant_id='grant-source' AND revision=1")
        checked = recovery.verify_history(self.store)
        self.assertFalse(checked['ok'])
        self.assertEqual(checked['problems'][0]['code'], 'grant_history_gap')
        self.assertEqual(checked['problems'][0]['grant_id'], 'grant-source')
        self.assertFalse(self.app.dispatch('system.check', {})['ok'])
        self.assertEqual(grants.get(self.store, 'grant-source')['revision'], 2)
