"""Standard-library statistics used by the drift diagnostics.

Everything here works on plain Python lists so the project keeps its
zero-dependency rule.  Numeric cells are converted to ``float`` only inside
this module; stored values keep their exact integer/decimal representation.

The functions are deliberately small and deterministic: no global random
state is used, callers hand in their own ``random.Random`` instance.
"""
import math

from rights_graph.primitives import count, reject

QUANTILES = (0.0, 0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99, 1.0)
# Categories beyond this many observed labels are folded into a single bucket.
MAX_CATEGORIES = 200
MISSING_CATEGORY = '\x00__missing__'
OTHER_CATEGORY = '\x00__other__'


def rounded(value, digits=6):
    """Round a finite statistic; ``None`` and non-finite values stay missing."""
    if value is None:
        return None
    if not math.isfinite(value):
        return None
    return round(float(value), digits)


def as_float(value):
    """Convert an authorized numeric/timestamp cell to float."""
    if isinstance(value, bool):
        reject('drift_numeric', 'Booleans are categorical, not numeric')
    if isinstance(value, (int, float)):
        return float(value)
    # Stored decimals are canonical strings, timestamps are ISO strings.
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        from rights_graph.primitives import GraphError
        raise GraphError('drift_numeric', 'Numeric column contains a non-numeric cell') from exc


def quantiles(values, points=QUANTILES):
    """Linear-interpolation empirical quantiles, matching the numpy default."""
    ordered = sorted(values)
    if not ordered:
        return {str(point): None for point in points}
    last = len(ordered) - 1
    result = {}
    for point in points:
        position = point * last
        lower = int(math.floor(position))
        upper = int(math.ceil(position))
        if lower == upper:
            estimate = ordered[lower]
        else:
            fraction = position - lower
            estimate = ordered[lower] * (1 - fraction) + ordered[upper] * fraction
        result[str(point)] = rounded(estimate)
    return result


def wasserstein_1(reference, candidate):
    """First Wasserstein distance on the real line.

    Exact for finite samples: the empirical CDFs are step functions that
    change only at the pooled, sorted unique support points, and the integral
    of the absolute CDF gap is a sum of rectangles over those points.
    """
    if not reference or not candidate:
        return None
    support = sorted(set(reference) | set(candidate))
    n_ref = len(reference)
    n_cand = len(candidate)
    ref_sorted = sorted(reference)
    cand_sorted = sorted(candidate)
    import bisect
    distance = 0.0
    previous = support[0]
    for point in support:
        cdf_ref = bisect.bisect_left(ref_sorted, point) / n_ref
        cdf_cand = bisect.bisect_left(cand_sorted, point) / n_cand
        distance += abs(cdf_ref - cdf_cand) * (point - previous)
        previous = point
    return distance


def _frequency_map(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return counts


def category_table(reference, candidate):
    """Frequencies including a dedicated missing category.

    High-cardinality columns are folded into one ``__other__`` bucket on each
    side independently, which keeps the output bounded and avoids turning a
    diagnostic into a dump of distinct label values.
    """
    ref_counts = _frequency_map(reference)
    cand_counts = _frequency_map(candidate)
    labels = sorted(set(ref_counts) | set(cand_counts), key=lambda item: str(item))
    folded = len(labels) > MAX_CATEGORIES
    if folded:
        # Keep the most common labels globally so both sides share a vocabulary.
        totals = {label: ref_counts.get(label, 0) + cand_counts.get(label, 0) for label in labels}
        kept = set(sorted(labels, key=lambda item: (-totals[item], str(item)))[:MAX_CATEGORIES - 1])
        ref_kept, cand_kept = {}, {}
        for label in labels:
            if label in kept:
                if label in ref_counts:
                    ref_kept[label] = ref_counts[label]
                if label in cand_counts:
                    cand_kept[label] = cand_counts[label]
            else:
                ref_kept[OTHER_CATEGORY] = ref_kept.get(OTHER_CATEGORY, 0) + ref_counts.get(label, 0)
                cand_kept[OTHER_CATEGORY] = cand_kept.get(OTHER_CATEGORY, 0) + cand_counts.get(label, 0)
        ref_counts, cand_counts = ref_kept, cand_kept
        labels = sorted(set(ref_counts) | set(cand_counts), key=lambda item: str(item))
    n_ref = len(reference)
    n_cand = len(candidate)
    rows = []
    for label in labels:
        rows.append({
            'category': None if label == MISSING_CATEGORY else label,
            'reference_count': ref_counts.get(label, 0),
            'reference_frequency': rounded(ref_counts.get(label, 0) / n_ref) if n_ref else None,
            'candidate_count': cand_counts.get(label, 0),
            'candidate_frequency': rounded(cand_counts.get(label, 0) / n_cand) if n_cand else None,
        })
    return {'categories': rows, 'folded': folded, 'reference_n': n_ref, 'candidate_n': n_cand}


def jensen_shannon(reference, candidate):
    """Jensen-Shannon divergence (natural log), its metric, and 0..1 form."""
    if not reference or not candidate:
        return None
    vocabulary = set(reference) | set(candidate)
    p_total = len(reference)
    q_total = len(candidate)
    p_counts = _frequency_map(reference)
    q_counts = _frequency_map(candidate)
    divergence = 0.0
    for label in vocabulary:
        p = p_counts.get(label, 0) / p_total
        q = q_counts.get(label, 0) / q_total
        m = (p + q) / 2
        if p > 0:
            divergence += 0.5 * p * math.log(p / m)
        if q > 0:
            divergence += 0.5 * q * math.log(q / m)
    divergence = max(0.0, divergence)
    return {
        'divergence_nats': rounded(divergence),
        'metric': rounded(math.sqrt(divergence)),
        'normalized': rounded(divergence / math.log(2)),
    }


def mean_variance(values):
    n = len(values)
    if n < 2:
        return (values[0] if n == 1 else None), None
    mean = sum(values) / n
    variance = sum((value - mean) ** 2 for value in values) / (n - 1)
    return mean, variance


def standardized_vectors(rows, field_names, reference_scales):
    """Project rows onto common numeric fields using reference-only scales.

    ``reference_scales`` maps a field to ``(mean, sample_std)`` derived solely
    from the reference version.  Constant or zero-variance reference fields
    cannot be standardized and are excluded by the caller.
    """
    vectors = []
    used = []
    for field in field_names:
        mean, std = reference_scales[field]
        if std is None or std == 0.0:
            continue
        used.append(field)
    for row in rows:
        if any(row.get(field) is None for field in used):
            continue
        vectors.append([(as_float(row[field]) - reference_scales[field][0]) / reference_scales[field][1] for field in used])
    return vectors, used


def energy_distance(reference_vectors, candidate_vectors):
    """Standardized energy distance between two samples in Euclidean space."""
    n = len(reference_vectors)
    m = len(candidate_vectors)
    if n < 2 or m < 2:
        return None

    def pair_sum(vectors_a, vectors_b):
        total = 0.0
        for left in vectors_a:
            for right in vectors_b:
                total += math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)))
        return total

    cross = pair_sum(reference_vectors, candidate_vectors)
    within_ref = pair_sum(reference_vectors, reference_vectors)
    within_cand = pair_sum(candidate_vectors, candidate_vectors)
    estimate = 2 * cross / (n * m) - within_ref / (n * n) - within_cand / (m * m)
    # Sample estimates can be slightly negative by finite-sample noise.
    return max(0.0, estimate)


def permutation_pvalue(observed, blocks_a, blocks_b, statistic, rng, permutations):
    """Block-permutation p-value.

    ``blocks_*`` are ``(label, rows)`` subject blocks.  Each permutation pools
    the blocks, shuffles subject labels, re-splits at the original row count
    and recomputes ``statistic(rows_a, rows_b)``.  Repeated subjects always
    move as one whole block, never row by row.  Unequal block sizes mean the
    re-split matches the target size as closely as the random allocation
    allows, which keeps the randomization distribution exchangeable under the
    null.
    """
    count(permutations, 'permutations', 1, 1000)
    pooled = list(blocks_a) + list(blocks_b)
    size_a = sum(len(block[1]) for block in blocks_a)
    labels = list(range(len(pooled)))
    weights = [len(block[1]) for block in pooled]
    exceed = 0
    evaluated = 0
    for _ in range(permutations):
        rng.shuffle(labels)
        membership = [0] * len(pooled)
        remaining = size_a
        for label in labels:
            weight = weights[label]
            if weight <= remaining:
                membership[label] = 1
                remaining -= weight
        rows_a, rows_b = [], []
        for label, block in enumerate(pooled):
            (rows_a if membership[label] else rows_b).extend(block[1])
        value = statistic(rows_a, rows_b)
        if value is None:
            continue
        evaluated += 1
        if value >= observed:
            exceed += 1
    if evaluated == 0:
        return None, 0
    return (exceed + 1) / (evaluated + 1), evaluated


def benjamini_hochberg(pvalues, alpha=0.05):
    """BH step-up adjustment over one analysis family.

    ``pvalues`` maps a stable test key to a raw p-value (missing tests are
    skipped).  Returns adjusted p-values and the rejection flags at ``alpha``.
    """
    valid = [(key, value) for key, value in pvalues.items() if value is not None]
    m = len(valid)
    adjusted = {key: None for key in pvalues}
    rejected = {key: False for key in pvalues}
    if not m:
        return {'adjusted': adjusted, 'rejected': rejected, 'family_size': 0, 'alpha': alpha}
    ordered = sorted(valid, key=lambda item: item[1])
    running = 1.0
    adjusted_values = [0.0] * m
    for rank_from_end in range(m, 0, -1):
        key, value = ordered[rank_from_end - 1]
        running = min(running, value * m / rank_from_end)
        adjusted_values[rank_from_end - 1] = min(1.0, running)
    largest_rank = 0
    for rank, (key, value) in enumerate(ordered, 1):
        adjusted[key] = rounded(adjusted_values[rank - 1])
        if value <= alpha * rank / m:
            largest_rank = rank
    for rank, (key, _) in enumerate(ordered, 1):
        rejected[key] = rank <= largest_rank
    return {'adjusted': adjusted, 'rejected': rejected, 'family_size': m, 'alpha': alpha}
