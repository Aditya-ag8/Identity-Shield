"""Small, dependency-free statistics used by the analysis layer.

The study is paired binary data, so the important pieces are Wilson intervals,
McNemar's exact test and a Kaplan-Meier estimator for latency. Keeping them
here (rather than importing scipy at runtime) makes the report reproducible in a
minimal environment.
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def _binom_two_sided(k: int, n: int) -> float:
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(k, n - k) + 1)) / (2**n)
    return min(1.0, 2 * tail)


def mcnemar_exact(baseline_only: int, improved_only: int) -> dict[str, float | int]:
    """Exact McNemar test on the discordant pairs.

    ``baseline_only`` = detected by round 1, missed by round 2.
    ``improved_only`` = missed by round 1, detected by round 2.
    """
    discordant = baseline_only + improved_only
    p = _binom_two_sided(min(baseline_only, improved_only), discordant)
    return {
        "baseline_only": baseline_only,
        "improved_only": improved_only,
        "discordant": discordant,
        "statistic": float(min(baseline_only, improved_only)),
        "p_value": p,
    }


def quantile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def kaplan_meier(
    durations: Iterable[float], observed: Iterable[bool]
) -> dict[str, object]:
    """Return the survival curve and median for right-censored durations.

    ``observed=False`` means the event never arrived (censored at the
    observation window); treating it as a short duration would bias the median
    downward.
    """
    pairs = sorted(zip(durations, observed), key=lambda pair: pair[0])
    at_risk = len(pairs)
    survival = 1.0
    curve: list[dict[str, float]] = []
    median: float | None = None
    for index, (duration, event_observed) in enumerate(pairs):
        if event_observed:
            survival *= (at_risk - 1) / at_risk if at_risk else 1.0
        at_risk -= 1
        curve.append({"t": float(duration), "survival": round(survival, 6)})
        if median is None and survival <= 0.5:
            median = float(duration)
    return {"curve": curve, "median": median, "n": len(pairs)}


def percentage(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0
