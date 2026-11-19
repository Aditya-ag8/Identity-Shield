"""Benign-activity generation (the false-alarm half of the study).

Attack variants answer "did the rule fire when it should?". Benign variants
answer the other half: "what does the rule cost when nothing is happening?".

They deliberately reuse the attack variant contract so the runner, trial table
and analysis code handle both without a second path. They are kept in a
separate file, ``data/variants/benign.jsonl``, so attack-space coverage numbers
can never include them.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from identity_shield import config
from identity_shield.contracts import Variant, spec_hash
from identity_shield.variants.generator import GenerationOptions
from identity_shield.variants.loader import Catalogue, CatalogueError, Technique


@dataclass(frozen=True)
class BenignActivity:
    activity_id: str
    technique_id: str
    name: str
    expected_alerts: int
    events: tuple[Mapping[str, Any], ...]


def load_benign(path: str | Path | None = None) -> tuple[BenignActivity, ...]:
    path = Path(path) if path else config.CONF / "benign.yaml"
    if not path.exists():
        return ()
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    activities: list[BenignActivity] = []
    for entry in document.get("activities") or []:
        events = entry.get("events")
        if not isinstance(events, list) or not events:
            raise CatalogueError(f"benign activity {entry.get('activity_id')!r} has no events")
        activities.append(
            BenignActivity(
                activity_id=str(entry.get("activity_id") or ""),
                technique_id=str(entry.get("technique_id") or ""),
                name=str(entry.get("name") or ""),
                expected_alerts=int(entry.get("expected_alerts") or 0),
                events=tuple(dict(event) for event in events),
            )
        )
    return tuple(activities)


def generate_benign(
    catalogue: Catalogue,
    *,
    options: GenerationOptions | None = None,
    activities: tuple[BenignActivity, ...] | None = None,
) -> tuple[Variant, ...]:
    """Two benign variants per activity: the default client and the AWS CLI.

    The second level is a real factor change, so the benign set also exercises
    the rule's client-tool sensitivity without inventing a new mechanism.
    """
    options = options or GenerationOptions()
    activities = activities if activities is not None else load_benign()
    known = {technique.technique_id for technique in catalogue.techniques}
    rows: list[Variant] = []

    for activity in activities:
        if activity.technique_id not in known:
            continue
        technique = catalogue.technique(activity.technique_id)
        baseline = catalogue.baseline_for(technique)
        alternatives = [dict(baseline)]
        if "client_tool" in catalogue.factors and technique.is_allowed("client_tool", "aws_cli"):
            alternative = dict(baseline)
            alternative["client_tool"] = "aws_cli"
            alternatives.append(alternative)

        for index, levels in enumerate(alternatives):
            digest = spec_hash(technique.technique_id, levels)
            rows.append(
                Variant(
                    variant_id=f"{technique.technique_id}-benign-{len(rows):03d}",
                    technique_id=technique.technique_id,
                    variant_set="benign",
                    factor_levels=levels,
                    seed=options.seed_for(activity.activity_id) + index,
                    spec_sha256=digest,
                    notes=activity.activity_id,
                )
            )
    # Duplicate specs can occur when two activities share a technique and the
    # same levels; keep the first, because the activity note is what differs.
    seen: set[str] = set()
    unique: list[Variant] = []
    for row in rows:
        if row.spec_sha256 in seen:
            continue
        seen.add(row.spec_sha256)
        unique.append(row)
    return tuple(unique)


def activity_for(variant: Variant, activities: tuple[BenignActivity, ...] | None = None) -> BenignActivity | None:
    activities = activities if activities is not None else load_benign()
    for activity in activities:
        if activity.activity_id == variant.notes:
            return activity
    return None


def benign_events(
    variant: Variant,
    activity: BenignActivity,
    *,
    run_id: str,
    start: str,
) -> list[dict[str, Any]]:
    """Build CloudTrail-shaped benign events, deterministically."""
    from identity_shield.runner.synthetic import build_event, parse_start

    moment = parse_start(start)
    client_tool = variant.factor_levels.get("client_tool", "boto3_default")
    events: list[dict[str, Any]] = []
    for index, template in enumerate(activity.events):
        event = build_event(
            technique_id=variant.technique_id,
            event_name=str(template.get("eventName")),
            event_source=str(template.get("eventSource")),
            run_id=run_id,
            variant_id=variant.variant_id,
            index=index,
            moment=moment,
            identity="instance_profile"
            if template.get("instance_context")
            else "iam_user",
            client_tool=client_tool,
            source_ip=str(template.get("source_ip") or "52.94.13.7"),
            request_parameters=dict(template.get("requestParameters") or {}),
        )
        if template.get("mfa_used"):
            event["additionalEventData"] = {"MFAUsed": str(template["mfa_used"])}
            event["responseElements"] = {"ConsoleLogin": "Success"}
        events.append(event)
    return events
