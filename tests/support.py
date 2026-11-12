import unittest
from rights_graph.service import RightsService
from rights_graph.primitives import GraphError
from rights_graph.catalog import assets, recipes
from rights_graph.policy import grants
from rights_graph.planner import plans, builds


def column(name='text', kind='string', classification='internal', nullable=False):
    return {'name': name, 'type': kind, 'classification': classification, 'nullable': nullable}


def policy(columns=None, **changes):
    value = {'purposes': ['research', 'search'], 'regions': ['cn', 'eu'], 'rights': ['read', 'transform', 'distribute'], 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2027-01-01T00:00:00Z', 'obligations': ['attribution'], 'columns': columns or ['text'], 'max_depth': 10, 'allow_derivatives': True}
    value.update(changes)
    return value


def context(**changes):
    value = {'purpose': 'research', 'region': 'cn', 'right': 'read', 'at': '2026-11-11T00:00:00Z', 'fulfilled_obligations': ['attribution']}
    value.update(changes)
    return value


def recipe(source='source', output='text', source_column='text', operator='copy', **extras):
    return {'inputs': [{'asset_id': source, 'alias': 'input'}], 'columns': [{'output': output, 'operator': operator, 'sources': [{'input': 'input', 'column': source_column}], **extras}], 'description': 'Synthetic derivation'}


class Case(unittest.TestCase):
    def setUp(self):
        self.time = '2026-11-11T00:00:00.000000Z'
        self.app = RightsService(clock=lambda: self.time)
        self.store = self.app.store
        self.addCleanup(self.app.close)

    def source(self, identity='source', columns=None, grant_id=None, grant_policy=None):
        columns = columns or [column()]
        assets.create(self.store, identity, 'source', 'owner', columns, 'Synthetic source')
        grants.create(self.store, grant_id or 'grant-' + identity, identity, grant_policy or policy([item['name'] for item in columns]))
        return assets.get(self.store, identity)

    def derived(self, identity='derived', source='source', columns=None, definition=None):
        assets.create(self.store, identity, 'derived', 'owner', columns or [column()], 'Synthetic derived asset')
        recipes.put(self.store, 'recipe-' + identity, identity, 0, definition or recipe(source))
        return assets.get(self.store, identity)

    def chain(self):
        self.source()
        self.derived()
        self.derived('final', 'derived')

    def build(self, target='derived', request=None, identity='build'):
        plan = plans.create(self.store, target, request or context())
        builds.create(self.store, identity, plan['plan_id'])
        result = builds.execute(self.store, identity)
        return plan, result['result']['target_artifact']

    def fails(self, code, function, *args, **kwargs):
        with self.assertRaises(GraphError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception
