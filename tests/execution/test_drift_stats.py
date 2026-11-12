import math

from tests.support import Case
from rights_graph.diagnostics import stats


class StatsTests(Case):
    def test_wasserstein_matches_known_shift(self):
        # Shifting every value by 2 moves the whole empirical CDF by 2.
        reference = [0.0, 1.0, 2.0, 3.0]
        candidate = [2.0, 3.0, 4.0, 5.0]
        self.assertAlmostEqual(stats.wasserstein_1(reference, candidate), 2.0)
        # Identical samples have zero distance.
        self.assertEqual(stats.wasserstein_1(reference, reference), 0.0)

    def test_wasserstein_unsorted_and_weighted_support(self):
        # Reference CDF: 0.5 on [0,2), 1 after; candidate: 1 on [1,2).
        # |CDF gap| is 0.5 over [0,1) and 1.0 over [1,2), integrating to 1.0.
        self.assertAlmostEqual(stats.wasserstein_1([0, 2], [1, 1]), 1.0)
        # A half-unit translation on equal two-point samples moves mass by 0.5.
        self.assertAlmostEqual(stats.wasserstein_1([0, 1], [0.5, 1.5]), 0.5)

    def test_jensen_shannon_bounds_and_identical_distribution(self):
        same = ['a', 'b', 'a', None]
        pack = stats.jensen_shannon(same, list(same))
        self.assertEqual(pack['divergence_nats'], 0.0)
        self.assertEqual(pack['metric'], 0.0)
        disjoint = stats.jensen_shannon(['a', 'a'], ['b', 'b'])
        self.assertAlmostEqual(disjoint['divergence_nats'], round(math.log(2), 6), places=5)
        self.assertAlmostEqual(disjoint['normalized'], 1.0)

    def test_quantiles_linear_interpolation(self):
        result = stats.quantiles([0.0, 10.0])
        keys = list(stats.QUANTILES)
        self.assertEqual(result[str(keys[0])], 0.0)
        self.assertEqual(result[str(keys[-1])], 10.0)
        self.assertEqual(result[str(0.5)], 5.0)
        self.assertEqual(stats.quantiles([])[str(0.5)], None)

    def test_benjamini_hochberg_step_up(self):
        # Four tests, the two smallest raw p-values are rejected at alpha 0.05.
        pvalues = {'a': 0.01, 'b': 0.02, 'c': 0.20, 'd': 0.90}
        bh = stats.benjamini_hochberg(pvalues, alpha=0.05)
        self.assertTrue(bh['rejected']['a'])
        self.assertTrue(bh['rejected']['b'])
        self.assertFalse(bh['rejected']['c'])
        self.assertFalse(bh['rejected']['d'])
        self.assertEqual(bh['family_size'], 4)
        # Adjusted p-values are monotone and never below the raw value.
        self.assertGreaterEqual(bh['adjusted']['a'], pvalues['a'])

    def test_energy_distance_zero_for_same_sample(self):
        vectors = [[0.0, 0.0], [1.0, 1.0], [2.0, 0.0], [1.0, 3.0]]
        self.assertEqual(stats.energy_distance(vectors, vectors), 0.0)
        self.assertIsNone(stats.energy_distance([[0.0]], [[1.0]]))

    def test_category_table_folds_high_cardinality(self):
        reference = [f'label-{index}' for index in range(stats.MAX_CATEGORIES + 50)]
        candidate = reference[:]
        table = stats.category_table(reference, candidate)
        self.assertTrue(table['folded'])
        self.assertLessEqual(len(table['categories']), stats.MAX_CATEGORIES)
        labels = {row['category'] for row in table['categories']}
        self.assertIn(stats.OTHER_CATEGORY, labels)

    def test_block_permutation_keeps_subjects_intact(self):
        import random
        blocks_a = [('a', [{'v': 1}, {'v': 1}]), ('b', [{'v': 1}])]
        blocks_b = [('c', [{'v': 9}, {'v': 9}]), ('d', [{'v': 9}])]

        def statistic(rows_a, rows_b):
            # Returns the group sizes so we can check the split is row-based.
            return (len(rows_a), len(rows_b))

        pvalue, evaluated = stats.permutation_pvalue(
            (3, 2), blocks_a, blocks_b, statistic, random.Random(7), 25)
        self.assertEqual(evaluated, 25)
        self.assertIsNotNone(pvalue)
        self.assertGreaterEqual(pvalue, 1 / 26)
