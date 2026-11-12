from rights_graph.primitives import fields, reject
from rights_graph.journal.store import Store
from rights_graph.journal import audit
from rights_graph.catalog import assets, recipes, importing
from rights_graph.policy import grants, analysis
from rights_graph.policy.proposals import ProposalDesk
from rights_graph.planner import plans, builds, artifacts, inspection, invalidation, topology, recovery
from rights_graph.planner.preview import PreviewEngine
from rights_graph.planner.campaigns import Campaigns
from rights_graph.planner.delivery import DeliveryDesk


class RightsService:
    def __init__(self, path=':memory:', **options):
        self.store = Store(path, **options)
        self.preview = PreviewEngine(self.store)
        self.proposals = ProposalDesk(self.store)
        self.campaigns = Campaigns(self.store)
        self.deliveries = DeliveryDesk(self.store)

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()

    def close(self):
        self.store.close()

    def dispatch(self, operation, data):
        if not isinstance(data, dict):
            reject('request_object', 'Request arguments must be an object')
        if operation == 'portfolio.assess':
            from rights_graph.policy.portfolios import assess
            fields(data, {'targets', 'requests'})
            return assess(self.store, **data)
        if operation == 'portfolio.columns':
            from rights_graph.policy.portfolios import minimal_columns
            fields(data, {'target', 'request'})
            return minimal_columns(self.store, **data)
        if operation == 'portfolio.obligations':
            from rights_graph.policy.portfolios import obligation_inventory
            fields(data, {'target'})
            return obligation_inventory(self.store, **data)
        if operation == 'portfolio.compare':
            from rights_graph.policy.portfolios import compare_contexts
            fields(data, {'target', 'before', 'after'})
            return compare_contexts(self.store, **data)
        if operation == 'data.csv':
            from rights_graph.catalog.tabular import import_csv
            fields(data, {'batch_id', 'asset_id', 'version', 'text'}, {'null_token', 'maximum_rows'})
            return import_csv(self.preview.data, **data)
        if operation == 'data.jsonlines':
            from rights_graph.catalog.tabular import import_jsonlines
            fields(data, {'batch_id', 'asset_id', 'version', 'text'}, {'maximum_rows'})
            return import_jsonlines(self.preview.data, **data)
        if operation == 'preview.csv':
            from rights_graph.catalog.tabular import export_csv
            fields(data, {'preview_id', 'artifact_id'}, {'null_token'})
            return export_csv(self.preview, **data)
        if operation == 'preview.jsonlines':
            from rights_graph.catalog.tabular import export_jsonlines
            fields(data, {'preview_id', 'artifact_id'})
            return export_jsonlines(self.preview, **data)
        if operation == 'catalog.import':
            return importing.import_catalog(self.store, data)
        if operation == 'catalog.export':
            fields(data, set())
            return importing.export_catalog(self.store)
        if operation == 'asset.create':
            fields(data, {'asset_id', 'kind', 'owner', 'columns', 'description'}, {'metadata', 'content_hash'})
            return assets.create(self.store, **data)
        if operation == 'asset.revise':
            fields(data, {'asset_id', 'expected_head', 'columns', 'description'}, {'metadata', 'content_hash', 'allow_breaking'})
            return assets.revise(self.store, **data)
        if operation == 'asset.retire':
            fields(data, {'asset_id', 'expected_head', 'reason'})
            return assets.retire(self.store, **data)
        if operation == 'asset.get':
            fields(data, {'asset_id'}, {'version'})
            return assets.get(self.store, **data)
        if operation == 'asset.list':
            fields(data, set(), {'kind', 'owner'})
            return assets.listing(self.store, **data)
        if operation == 'asset.history':
            fields(data, {'asset_id'})
            return assets.versions(self.store, **data)
        if operation == 'asset.explain':
            fields(data, {'asset_id'})
            return inspection.explain_asset(self.store, **data)
        if operation == 'asset.impact':
            fields(data, {'asset_id', 'candidate_schema'})
            return inspection.dependency_change_impact(self.store, **data)
        if operation == 'grant.create':
            fields(data, {'grant_id', 'asset_id', 'policy'})
            return grants.create(self.store, **data)
        if operation == 'grant.revise':
            fields(data, {'grant_id', 'expected_revision', 'policy', 'reason'})
            return grants.revise(self.store, **data)
        if operation == 'grant.revoke':
            fields(data, {'grant_id', 'expected_revision', 'reason'})
            return grants.revoke(self.store, **data)
        if operation == 'grant.get':
            fields(data, {'grant_id'}, {'revision'})
            return grants.get(self.store, **data)
        if operation == 'grant.list':
            fields(data, {'asset_id'}, {'active_only'})
            return grants.for_asset(self.store, **data)
        if operation == 'grant.history':
            fields(data, {'grant_id'})
            return grants.history(self.store, **data)
        if operation == 'grant.alternatives':
            fields(data, {'asset_id', 'columns', 'request'}, {'depth'})
            return analysis.alternatives(self.store, **data)
        if operation == 'grant.coverage':
            fields(data, {'asset_id', 'requests'})
            return analysis.coverage_matrix(self.store, **data)
        if operation == 'grant.impact':
            fields(data, {'grant_id'})
            return analysis.revocation_impact(self.store, **data)
        if operation == 'grant.expiry':
            fields(data, {'start', 'end'})
            return analysis.expiry_calendar(self.store, **data)
        if operation == 'grant.compare':
            fields(data, {'grant_id', 'before', 'after'})
            return analysis.compare_grant_versions(self.store, **data)
        if operation == 'recipe.put':
            fields(data, {'recipe_id', 'output_asset', 'expected_revision', 'definition'})
            return recipes.put(self.store, **data)
        if operation == 'recipe.get':
            fields(data, {'recipe_id'})
            return recipes.get(self.store, **data)
        if operation == 'recipe.list':
            fields(data, set())
            return recipes.listing(self.store)
        if operation == 'recipe.history':
            fields(data, {'recipe_id'})
            return recipes.history(self.store, **data)
        if operation == 'plan.create':
            fields(data, {'target', 'context'}, {'columns', 'grant_overrides'})
            return plans.create(self.store, **data)
        if operation == 'plan.get':
            fields(data, {'plan_id'})
            return plans.get(self.store, **data)
        if operation == 'plan.freshness':
            fields(data, {'plan_id'})
            return plans.freshness(self.store, **data)
        if operation == 'plan.compare':
            fields(data, {'before', 'after'})
            return plans.compare(self.store, **data)
        if operation == 'build.create':
            fields(data, {'build_id', 'plan_id'})
            return builds.create(self.store, **data)
        if operation == 'build.get':
            fields(data, {'build_id'})
            return builds.get(self.store, **data)
        if operation == 'build.claim':
            fields(data, {'build_id', 'owner'}, {'ttl'})
            return builds.claim(self.store, **data)
        if operation == 'build.heartbeat':
            fields(data, {'build_id', 'token'}, {'ttl'})
            return builds.heartbeat(self.store, **data)
        if operation == 'build.step':
            fields(data, {'build_id', 'token'})
            return builds.run_step(self.store, **data)
        if operation == 'build.finalize':
            fields(data, {'build_id', 'token'})
            return builds.finalize(self.store, **data)
        if operation == 'build.execute':
            fields(data, {'build_id'}, {'owner', 'ttl'})
            return builds.execute(self.store, **data)
        if operation == 'build.cancel':
            fields(data, {'build_id', 'expected_revision', 'reason'})
            return builds.cancel(self.store, **data)
        if operation == 'build.checkpoint':
            fields(data, {'build_id'})
            return recovery.checkpoint(self.store, **data)
        if operation == 'build.resume':
            fields(data, {'build_id'}, {'owner'})
            return recovery.resume(self.store, **data)
        if operation == 'build.replan':
            fields(data, {'old_build_id', 'new_build_id'}, {'context'})
            return recovery.replan(self.store, **data)
        if operation == 'artifact.verify':
            fields(data, {'artifact_id'}, {'request'})
            return artifacts.verify(self.store, **data)
        if operation == 'artifact.export':
            fields(data, {'artifact_id'}, {'request'})
            return artifacts.export(self.store, **data)
        if operation == 'artifact.withdraw':
            fields(data, {'artifact_id', 'reason'})
            return artifacts.withdraw(self.store, **data)
        if operation == 'artifact.proof':
            fields(data, {'artifact_id'})
            return inspection.artifact_proof(self.store, **data)
        if operation == 'data.import':
            fields(data, {'batch_id', 'asset_id', 'version', 'rows'})
            return self.preview.data.import_rows(**data)
        if operation == 'data.verify':
            fields(data, {'batch_id'})
            return self.preview.data.verify(**data)
        if operation == 'preview.run':
            fields(data, {'plan_id', 'bindings'}, {'limit'})
            return self.preview.run(**data)
        if operation == 'preview.export':
            fields(data, {'preview_id', 'artifact_id'})
            return self.preview.export(**data)
        if operation == 'proposal.submit':
            fields(data, {'proposal_id', 'grant_id', 'candidate', 'author', 'reason'})
            return self.proposals.submit(**data)
        if operation == 'proposal.review':
            fields(data, {'proposal_id', 'reviewer', 'accept', 'reason', 'expected_analysis_hash'})
            return self.proposals.review(**data)
        if operation == 'proposal.refresh':
            fields(data, {'proposal_id', 'author'})
            return self.proposals.refresh(**data)
        if operation == 'campaign.create':
            fields(data, {'campaign_id', 'requests'})
            return self.campaigns.create(**data)
        if operation == 'campaign.advance':
            fields(data, {'campaign_id'}, {'owner'})
            return self.campaigns.advance(**data)
        if operation == 'campaign.close':
            fields(data, {'campaign_id'}, {'allow_partial'})
            return self.campaigns.close(**data)
        if operation == 'campaign.retry':
            fields(data, {'campaign_id', 'ordinal'})
            return self.campaigns.retry(**data)
        if operation == 'campaign.report':
            fields(data, {'campaign_id'})
            return self.campaigns.report(**data)
        if operation == 'delivery.prepare':
            fields(data, {'delivery_id', 'artifact_id', 'recipient', 'request'})
            return self.deliveries.prepare(**data)
        if operation == 'delivery.acknowledge':
            fields(data, {'delivery_id', 'recipient', 'expected_digest', 'receipt_id'})
            return self.deliveries.acknowledge(**data)
        if operation == 'delivery.reconcile':
            fields(data, {'at'})
            return self.deliveries.reconcile(**data)
        if operation == 'delivery.alerts':
            fields(data, set(), {'recipient', 'pending_only'})
            return self.deliveries.alerts(**data)
        if operation == 'delivery.acknowledge_alert':
            fields(data, {'alert_id', 'recipient'})
            return self.deliveries.acknowledge_alert(**data)
        if operation == 'audit.page':
            fields(data, set(), {'after', 'limit'})
            return audit.page(self.store, **data)
        if operation == 'audit.verify':
            fields(data, set())
            return audit.verify(self.store)
        if operation == 'graph.summary':
            fields(data, set())
            return topology.summary(self.store)
        if operation == 'system.check':
            fields(data, set())
            result = inspection.check(self.store)
            result['history'] = recovery.verify_history(self.store)
            result['ok'] = result['ok'] and result['history']['ok']
            return result
        if operation == 'system.overview':
            fields(data, set())
            return inspection.overview(self.store)
        reject('unknown_operation', 'Unknown service operation', operation=operation)

    def transaction(self, requests):
        if not isinstance(requests, list) or not 1 <= len(requests) <= 100:
            reject('transaction_requests', 'Atomic request batch must contain one to one hundred operations')
        with self.store.atomic():
            results = []
            for request in requests:
                fields(request, {'operation', 'arguments'})
                results.append(self.dispatch(request['operation'], request['arguments']))
            return results
