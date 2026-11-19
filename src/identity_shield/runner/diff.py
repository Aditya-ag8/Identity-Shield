"""Validity gate: did the variant actually change the log record?

The offline gate in Module 4 checks that each variant *declares* a non-empty
expected surface. This is the live half: compare the events captured for the
variant with the baseline for the same technique. A variant that produces
byte-identical evidence is an infrastructure failure, not an evasion, and is
excluded from the detection-rate denominator by the analysis layer.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from identity_shield.detect.rules import get_field


def _values(events: Sequence[Mapping[str, Any]], path: str) -> set[str]:
    return {json.dumps(get_field(event, path), sort_keys=True, default=str) for event in events}


def compare(
    baseline_events: Sequence[Mapping[str, Any]],
    variant_events: Sequence[Mapping[str, Any]],
    expected_surface: Sequence[str],
) -> dict[str, Any]:
    changed = [
        path for path in expected_surface if _values(baseline_events, path) != _values(variant_events, path)
    ]
    baseline_names = sorted({str(event.get("eventName")) for event in baseline_events})
    variant_names = sorted({str(event.get("eventName")) for event in variant_events})
    return {
        "variant_changed": bool(changed),
        "changed_fields": changed,
        "expected_surface": list(expected_surface),
        "baseline_event_names": baseline_names,
        "variant_event_names": variant_names,
        "baseline_events": len(baseline_events),
        "variant_events": len(variant_events),
    }


def compare_trials(conn, trial_id: str, baseline_trial_id: str, expected_surface: Sequence[str]) -> dict[str, Any]:
    def load(trial: str) -> list[dict[str, Any]]:
        rows = conn.execute("SELECT raw FROM event WHERE trial_id = ?", (trial,)).fetchall()
        events = []
        for row in rows:
            try:
                events.append(json.loads(row["raw"]))
            except json.JSONDecodeError:
                continue
        return events

    return compare(load(baseline_trial_id), load(trial_id), expected_surface)
