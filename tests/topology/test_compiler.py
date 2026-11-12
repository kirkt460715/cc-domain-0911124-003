from tests.support import Case, column, policy, context, recipe
from rights_graph.catalog import assets, recipes, linting
from rights_graph.policy import grants
from rights_graph.planner import topology, plans, artifacts
from rights_graph.planner.lineage import compile_graph, trace_column


class CompilerTests(Case):
    def test_chain_order_depth_and_trace(self):
        self.chain()
        compiled = compile_graph(self.store, 'final', context())
        self.assertEqual([step['asset_id'] for step in compiled['steps']], ['source', 'derived', 'final'])
        traced = trace_column(compiled, 'text')
        self.assertEqual(traced['lineage'][0]['depth'], 2)
        self.assertEqual(traced['lineage'][0]['path'], ['source.text', 'derived.text', 'final.text'])
        self.assertEqual(traced['lineage'][0]['grant_id'], 'grant-source')
        self.assertEqual(traced['policy']['obligations'], ['attribution'])
        self.assertEqual(compiled['result']['columns'], ['text'])
        self.fails('unknown_output_column', trace_column, compiled, 'missing')

    def test_cycle_rejected_atomically(self):
        self.chain()
        original = recipes.get(self.store, 'recipe-derived')
        self.fails('graph_cycle', recipes.put, self.store, 'recipe-derived', 'derived', 1, recipe('final'))
        self.assertEqual(recipes.get(self.store, 'recipe-derived')['revision'], 1)
        self.assertEqual(recipes.get(self.store, 'recipe-derived')['digest'], original['digest'])
        graph = topology.adjacency(self.store)
        self.assertEqual(topology.ancestors(graph, 'final'), ['source', 'derived'])
        self.assertEqual(topology.descendants(graph, 'source'), ['derived', 'final'])
        self.assertEqual(topology.paths(graph, 'source', 'final')['paths'], [['source', 'derived', 'final']])
        self.assertEqual(len(recipes.history(self.store, 'recipe-derived')), 1)

    def test_selected_columns_prune_unlicensed_branch(self):
        self.source('left')
        self.source('right', grant_policy=policy(regions=['eu']))
        columns = [column('a'), column('b')]
        definition = {'inputs': [{'asset_id': 'left', 'alias': 'l'}, {'asset_id': 'right', 'alias': 'r'}], 'columns': [{'output': 'a', 'operator': 'copy', 'sources': [{'input': 'l', 'column': 'text'}]}, {'output': 'b', 'operator': 'copy', 'sources': [{'input': 'r', 'column': 'text'}]}], 'description': 'Two independent columns'}
        self.derived(columns=columns, definition=definition)
        compiled = compile_graph(self.store, 'derived', context(), ['a'])
        self.assertEqual([step['asset_id'] for step in compiled['steps']], ['left', 'derived'])
        self.assertEqual(compiled['result']['columns'], ['a'])
        self.assertEqual(compiled['result']['lineage']['a'][0]['asset_id'], 'left')
        self.fails('authorization_denied', compile_graph, self.store, 'derived', context())
        self.fails('unused_grant_override', compile_graph, self.store, 'derived', context(), ['a'], {'right': 'grant-right'})

    def test_grant_choice_prefers_smallest_cover(self):
        self.source(columns=[column('text'), column('extra')])
        grants.create(self.store, 'narrow', 'source', policy(['text']))
        self.derived()
        compiled = compile_graph(self.store, 'derived', context())
        self.assertEqual(compiled['result']['lineage']['text'][0]['grant_id'], 'narrow')
        override = compile_graph(self.store, 'derived', context(), grant_overrides={'source': 'grant-source'})
        self.assertEqual(override['result']['lineage']['text'][0]['grant_id'], 'grant-source')
        self.assertNotEqual(override['result']['signature'], compiled['result']['signature'])
        self.fails('authorization_denied', compile_graph, self.store, 'derived', context(), grant_overrides={'source': 'missing'})

    def test_depth_limit_is_longest_shared_path(self):
        self.source(grant_policy=policy(max_depth=1))
        self.derived('middle')
        definition = {'inputs': [{'asset_id': 'source', 'alias': 'a'}, {'asset_id': 'middle', 'alias': 'z'}], 'columns': [{'output': 'text', 'operator': 'concat', 'sources': [{'input': 'a', 'column': 'text'}, {'input': 'z', 'column': 'text'}]}], 'description': 'Shared upstream via two paths'}
        self.derived('final', definition=definition)
        self.fails('authorization_denied', compile_graph, self.store, 'final', context())
        grants.revise(self.store, 'grant-source', 1, policy(max_depth=2), 'Permit two stages')
        result = compile_graph(self.store, 'final', context())
        self.assertEqual(len(result['steps']), 3)
        self.assertEqual(sorted(leaf['depth'] for leaf in result['result']['lineage']['text']), [1, 2])
        self.assertEqual(result['result']['policy']['max_depth'], 2)
        self.assertEqual(result['steps'][0]['asset_id'], 'source')

    def test_transform_permission_required(self):
        self.source(grant_policy=policy(rights=['read']))
        self.derived()
        self.assertEqual(compile_graph(self.store, 'source', context())['result']['columns'], ['text'])
        self.fails('authorization_denied', compile_graph, self.store, 'derived', context())
        grants.revise(self.store, 'grant-source', 1, policy(allow_derivatives=False), 'No derivation')
        self.fails('authorization_denied', compile_graph, self.store, 'derived', context())
        grants.revise(self.store, 'grant-source', 2, policy(), 'Permit derivation')
        self.assertEqual(len(compile_graph(self.store, 'derived', context())['steps']), 2)

    def test_pinned_source_stays_fresh_after_revision(self):
        self.source()
        definition = recipe()
        definition['inputs'][0]['version'] = 1
        self.derived(definition=definition)
        plan, artifact = self.build()
        assets.revise(self.store, 'source', 1, [column()], 'New source content')
        self.assertTrue(plans.freshness(self.store, plan['plan_id'])['fresh'])
        self.assertTrue(artifacts.verify(self.store, artifact)['valid'])
        self.assertEqual(assets.get(self.store, 'source')['version'], 2)
        self.assertEqual(plan['payload']['steps'][0]['version'], 1)
        self.assertTrue(plan['payload']['steps'][0]['pinned'])

    def test_pinned_retirement_still_invalidates(self):
        self.source()
        definition = recipe()
        definition['inputs'][0]['version'] = 1
        self.derived(definition=definition)
        plan, artifact = self.build()
        assets.retire(self.store, 'source', 1, 'No longer available')
        self.assertFalse(plans.freshness(self.store, plan['plan_id'])['fresh'])
        self.assertFalse(artifacts.verify(self.store, artifact)['valid'])
        self.assertEqual(artifacts.get(self.store, artifact)['status'], 'invalid')
        self.fails('lineage_retired', compile_graph, self.store, 'source', context())

    def test_derived_version_pin_not_supported(self):
        self.source()
        self.derived()
        definition = recipe('derived')
        definition['inputs'][0]['version'] = 1
        self.derived('final', definition=definition)
        self.fails('derived_pin', compile_graph, self.store, 'final', context())
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM plans'), 0)
        self.assertEqual(recipes.for_output(self.store, 'final')['definition']['inputs'][0]['version'], 1)
        self.assertEqual(len(assets.listing(self.store)), 3)
        self.assertEqual(len(recipes.listing(self.store)), 2)

    def test_redaction_keeps_obligations(self):
        self.source(columns=[column(classification='sensitive')])
        self.derived(columns=[column(classification='public', nullable=True)], definition=recipe(operator='redact', reason='Remove identifying content'))
        result = compile_graph(self.store, 'derived', context())
        self.assertEqual(result['result']['classification'], 'public')
        self.assertEqual(result['result']['policy']['obligations'], ['attribution'])
        self.assertEqual(result['result']['lineage']['text'][0]['asset_id'], 'source')
        self.fails('authorization_denied', compile_graph, self.store, 'derived', context(fulfilled_obligations=[]))
        self.fails('classification_denied', compile_graph, self.store, 'derived', context(maximum_classification='public'))
        self.assertEqual(result['result']['lineage']['text'][0]['depth'], 1)

    def test_silent_downgrade_rejected(self):
        self.source(columns=[column(classification='restricted')])
        assets.create(self.store, 'derived', 'derived', 'owner', [column(classification='public')], 'Public result')
        self.fails('recipe_downgrade', recipes.put, self.store, 'r', 'derived', 0, recipe())
        self.fails('recipe_downgrade', recipes.put, self.store, 'r', 'derived', 0, recipe(operator='hash'))
        self.assertEqual(recipes.listing(self.store), [])
        self.assertEqual(self.store.scalar('SELECT COUNT(*) FROM dependencies'), 0)
        self.assertEqual(assets.get(self.store, 'derived')['head'], 1)
        self.assertEqual(len(assets.listing(self.store)), 2)

    def test_recipe_requires_full_output_and_unique_aliases(self):
        self.source()
        assets.create(self.store, 'derived', 'derived', 'owner', [column(), column('extra')], 'Two columns')
        self.fails('recipe_incomplete', recipes.put, self.store, 'r', 'derived', 0, recipe())
        definition = recipe()
        definition['inputs'].append(dict(definition['inputs'][0]))
        self.fails('recipe_alias', recipes.put, self.store, 'r', 'derived', 0, definition)
        self.assertEqual(recipes.listing(self.store), [])
        definition = recipe()
        definition['columns'][0]['sources'][0]['column'] = 'missing'
        self.fails('recipe_source_column', recipes.put, self.store, 'r', 'derived', 0, definition)

    def test_column_consumers_and_lint(self):
        self.chain()
        result = linting.column_graph(self.store, 'final')
        self.assertEqual(len(result['nodes']), 3)
        self.assertEqual(len(result['edges']), 2)
        consumers = linting.consumers_of_column(self.store, 'source', 'text')
        self.assertEqual([row['asset_id'] for row in consumers['consumers']], ['derived', 'final'])
        self.assertEqual(consumers['consumers'][0]['columns'], ['text'])
        checked = linting.lint(self.store, context())
        self.assertTrue(checked['ok'])
        self.assertEqual(checked['counts']['error'], 0)
        self.fails('unknown_column', linting.consumers_of_column, self.store, 'source', 'missing')

    def test_schema_compatibility_and_impact(self):
        self.source(columns=[column(), column('spare')])
        self.derived()
        self.fails('breaking_schema', assets.revise, self.store, 'source', 1, [column('spare')], 'Removed text')
        self.assertEqual(assets.get(self.store, 'source')['head'], 1)
        from rights_graph.planner.inspection import dependency_change_impact
        impact = dependency_change_impact(self.store, 'source', [column('spare')])
        self.assertFalse(impact['schema_compatibility']['compatible'])
        self.assertEqual(impact['direct_consumers'][0]['missing_columns'], ['text'])
        self.assertTrue(impact['direct_consumers'][0]['affected'])
        self.assertEqual(impact['transitive_consumers'], ['derived'])
