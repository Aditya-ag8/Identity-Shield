"""Report generation.

The report is generated from the database, not from prose typed after the
fact. Every number carries its denominator, and the provenance section makes a
synthetic rehearsal impossible to mistake for a live result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from identity_shield import config
from identity_shield.analysis import misses, outcomes
from identity_shield.contracts import TeardownReport, read_json, utc_now
from identity_shield.variants.loader import Catalogue


def _read_coverage() -> dict[str, Any] | None:
    path = config.VARIANTS_DIR / "coverage.json"
    if not path.exists():
        return None
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def _read_teardown() -> dict[str, Any] | None:
    directory = config.LAB_DIR
    if not directory.exists():
        return None
    reports = sorted(directory.glob("teardown-*.json"))
    if not reports:
        return None
    try:
        document = read_json(reports[-1])
        TeardownReport.from_dict(document)
        return document
    except (OSError, ValueError, TypeError):
        return None


def _pct(value: float | int | None) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.1%}"


def _metric_row(name: str, entry: Mapping[str, Any]) -> str:
    return (
        f"| {name} | {entry['valid']} | {entry['detected']} | "
        f"{_pct(entry['detection_rate'])} | {_pct(entry['evasion_rate'])} | "
        f"{_pct(entry['wilson_low'])}-{_pct(entry['wilson_high'])} |"
    )


def build(
    conn,
    catalogue: Catalogue,
    *,
    ruleset: str = "baseline-v1",
    improved: str = "improved-v1",
    run_id: str | None = None,
    include_holdout: bool = False,
) -> dict[str, Any]:
    summary = outcomes.summarise(
        conn, ruleset, run_id=run_id, include_holdout=include_holdout
    )
    try:
        improved_summary = outcomes.summarise(
            conn, improved, run_id=run_id, include_holdout=include_holdout
        )
        paired = outcomes.paired(conn, ruleset, improved, run_id=run_id)
        diff = outcomes.rule_diff(conn, ruleset, improved)
    except Exception:  # noqa: BLE001 - report still renders with one ruleset
        improved_summary = None
        paired = None
        diff = None

    findings = misses.build(
        conn, catalogue, ruleset, run_id=run_id, include_holdout=include_holdout
    )
    bundle = {
        "generated_at": utc_now(),
        "provenance": summary["provenance"],
        "run_id": run_id,
        "baseline": summary,
        "improved": improved_summary,
        "paired": paired,
        "rule_diff": diff,
        "false_alarms": {
            "baseline": outcomes.false_alarms(conn, ruleset, run_id=run_id),
            "improved": outcomes.false_alarms(conn, improved, run_id=run_id),
        },
        "latency": {
            "baseline": outcomes.latency(conn, ruleset, run_id=run_id),
            "improved": outcomes.latency(conn, improved, run_id=run_id),
        },
        "findings": findings.to_dict(),
        "coverage": _read_coverage(),
        "teardown": _read_teardown(),
    }
    bundle["markdown"] = render(bundle)
    return bundle


def render(bundle: Mapping[str, Any]) -> str:
    baseline = bundle["baseline"]
    improved = bundle.get("improved")
    provenance = baseline["provenance"]
    synthetic = provenance["synthetic_trials"] > 0 and provenance["live_trials"] == 0

    lines = [
        "# Identity Shield - detection robustness report",
        "",
        f"Generated: {bundle['generated_at']}",
        f"Run: {bundle.get('run_id') or 'all runs'}",
        "",
        "## Provenance",
        "",
        f"- Live trials: **{provenance['live_trials']}**",
        f"- Synthetic rehearsal trials: **{provenance['synthetic_trials']}**",
        f"- Holdout included: **{'yes' if provenance['holdout_included'] else 'no'}**",
        "",
    ]
    if synthetic:
        lines += [
            "> **This report is a synthetic rehearsal.** Events were derived from the",
            "> hand-written fixtures, not captured from AWS. Use it to verify the",
            "> pipeline; do not cite its evasion numbers as findings.",
            "",
        ]
    elif provenance["synthetic_trials"]:
        lines += [
            "> Synthetic rehearsal rows are present. They are labelled per trial and must",
            "> be excluded before a live result is published.",
            "",
        ]

    lines += [
        "## Headline",
        "",
        "Detection is computed over **valid** trials only: the attack verified and the",
        "variant actually changed the captured evidence. Invalid or unverified trials",
        "are reported, not counted as evasions.",
        "",
        "| Rule set | Valid | Detected | Detection | Evasion | Wilson 95% |",
        "|---|---|---|---|---|---|",
        _metric_row("baseline-v1", baseline["overall"]),
    ]
    if improved:
        lines.append(_metric_row("improved-v1", improved["overall"]))
    lines += [
        "",
        "A trial counts as detected when **any** rule in the set raises an alert on",
        "one of its events, as pre-registered in the plan. A broad rule can therefore",
        "cover a miss by a technique-specific rule; the per-rule alert counts and the",
        "rule diff below show which rules did the work.",
        "",
    ]

    if bundle.get("paired"):
        paired = bundle["paired"]
        test = paired["mcnemar"]
        lines += [
            "## Paired comparison",
            "",
            f"Paired trials: **{paired['pairs']}**. Baseline detected "
            f"**{paired['baseline_detection_rate']:.1%}**, improved detected "
            f"**{paired['improved_detection_rate']:.1%}** (delta "
            f"**{paired['delta']:+.1%}**).",
            "",
            f"McNemar exact: baseline-only detections **{test['baseline_only']}**, "
            f"improved-only detections **{test['improved_only']}**, "
            f"p = **{test['p_value']:.4g}**.",
            "",
            "> At the planned sample size the test can distinguish a large swing, not",
            "> a 3-point difference. Report the interval, not just the p-value.",
            "",
        ]

    lines += [
        "## Per technique",
        "",
        "| Technique | Valid | Detected | Detection | Evasion | Wilson 95% |",
        "|---|---|---|---|---|---|",
    ]
    for technique, entry in baseline["techniques"].items():
        lines.append(_metric_row(technique, entry))
    lines += [
        "",
        "## Factor-level evasion",
        "",
        "Evasion rate for each level of each factor, over valid trials. This is the",
        "table behind the heatmap.",
        "",
        "| Factor | Level | Trials | Evasion |",
        "|---|---|---|---|",
    ]
    for factor, levels in baseline["factor_levels"].items():
        for level, entry in levels.items():
            lines.append(
                f"| {factor} | {level} | {entry['n']} | {_pct(entry['evasion_rate'])} |"
            )

    fa = bundle["false_alarms"]["baseline"]
    improved_fa = bundle["false_alarms"].get("improved")
    lines += [
        "",
        "## False alarms",
        "",
        f"Baseline benign trials: **{fa['trials']}**. Alerted: **{fa['alerted']}** "
        f"({_pct(fa['rate'])}, Wilson {_pct(fa['wilson_low'])}-{_pct(fa['wilson_high'])}).",
    ]
    if improved_fa:
        lines.append(
            f"Improved benign trials: **{improved_fa['trials']}**. Alerted: "
            f"**{improved_fa['alerted']}** ({_pct(improved_fa['rate'])}, Wilson "
            f"{_pct(improved_fa['wilson_low'])}-{_pct(improved_fa['wilson_high'])})."
        )
    lines.append("")
    if fa["by_technique"]:
        lines += ["| Benign activity context | Trials | Baseline alerts | Improved alerts |", "|---|---|---|---|"]
        improved_by = (improved_fa or {}).get("by_technique", {})
        for technique, entry in fa["by_technique"].items():
            improved_entry = improved_by.get(technique, {})
            lines.append(
                f"| {technique} | {entry['trials']} | {entry['alerted']} | "
                f"{improved_entry.get('alerted', 0)} |"
            )
        lines.append("")

    latency = bundle["latency"]["baseline"]
    lines += ["## Latency", ""]
    if latency.get("live"):
        lines += [
            f"Ingest lag (CloudTrail event time to SQLite receipt): median "
            f"**{latency['ingest_lag_ms']['median']} ms**, p95 **{latency['ingest_lag_ms']['p95']} ms** "
            f"over {latency['ingest_lag_ms']['n']} events.",
            "",
            f"Replay rule latency: median **{latency['rule_latency_ms']['median']} ms** over "
            f"{latency['rule_latency_ms']['n']} alerts. Replay timestamps measure evaluation,",
            "not live alert delivery; do not present them as time-to-detect.",
            "",
        ]
    else:
        lines += [
            "Not measured. This report contains no live trials, and a synthetic",
            "rehearsal clock cannot produce a meaningful ingest or delivery latency.",
            "",
        ]

    findings = bundle["findings"]
    lines += [
        "## Miss findings",
        "",
        f"**{findings['summary']['total']}** missed valid variants. Each finding records the",
        "variant's expected surface, the fields the rule set inspects, and the overlap.",
        "",
    ]
    for finding in findings["findings"][:40]:
        levels = ", ".join(f"{key}={value}" for key, value in finding["factor_levels"].items())
        lines.append(f"- **{finding['technique_id']} / {finding['variant_id']}** ({levels})")
        lines.append(f"  - {finding['rationale']}")
    if findings["summary"]["total"] > 40:
        lines.append(f"- ... {findings['summary']['total'] - 40} more in `data/findings.json`.")
    lines.append("")

    if bundle.get("rule_diff"):
        diff = bundle["rule_diff"]
        lines += [
            "## Rule diff",
            "",
            f"Baseline rules: **{diff['counts']['baseline']}**, improved rules: "
            f"**{diff['counts']['improved']}**, added: **{diff['counts']['added']}**, "
            f"removed: **{diff['counts']['removed']}**.",
            "",
        ]
        for row in diff["added"]:
            lines.append(f"- Added `{row['native_id']}`: {row['title']}")
        for row in diff["removed"]:
            lines.append(f"- Removed `{row['native_id']}`: {row['title']}")
        lines.append("")

    coverage = bundle.get("coverage")
    if coverage:
        levels = coverage["level_coverage"]
        pairs = coverage["pair_coverage"]
        lines += [
            "## Coverage appendix",
            "",
            f"- Variants: **{coverage['totals']['total']}** "
            f"(baseline {coverage['totals']['baseline']}, OFAT {coverage['totals']['ofat']}, "
            f"pairwise {coverage['totals']['pairwise']}, holdout {coverage['totals']['holdout']} sealed)",
            f"- Factor levels covered: **{levels['covered']}/{levels['levels']}** ({levels['ratio']:.0%})",
            f"- Pairwise coverage (minimum): **{pairs['min_ratio']:.0%}**",
            f"- Invalid variants: **{coverage['invalid_variants']}**",
            "",
        ]

    teardown = bundle.get("teardown")
    if teardown:
        lines += [
            "## Lab teardown",
            "",
            f"Run `{teardown['run_id']}`: before **{len(teardown['before'])}** resources, "
            f"after **{len(teardown['after'])}**, residue **{len(teardown['residue'])}**. "
            f"Verdict: **{'PASS' if teardown.get('passed') else 'FAIL'}**.",
            "",
        ]
    else:
        lines += [
            "## Lab teardown",
            "",
            "No teardown report found. The zero-residue claim is unproven until",
            "`identity-shield lab down --yes` has run against the lab account.",
            "",
        ]

    lines += [
        "## Limitations",
        "",
        "- Fixtures are hand-written from AWS documentation until the live collector replaces them.",
        "- No live `terraform apply`/`destroy` has run in this environment; the harness is code-tested only.",
        "- `nat_a`/`nat_b` egress and federated-session infrastructure are not provisioned yet.",
        "- T1552.005 has no IMDS event by construction; its detection is a behavioural proxy.",
        "- The holdout is sealed and excluded until the round-2 rules are frozen.",
        "",
        "## Reproduce",
        "",
        "```powershell",
        "identity-shield demo",
        "identity-shield variants generate",
        "identity-shield variants benign",
        "identity-shield runner campaign --synthetic --yes",
        "identity-shield analyse report",
        "```",
        "",
    ]
    return "\n".join(lines)


def write(bundle: Mapping[str, Any], *, directory: Path | None = None) -> tuple[Path, Path]:
    directory = directory or config.DATA
    directory.mkdir(parents=True, exist_ok=True)
    markdown_path = directory / "report.md"
    json_path = directory / "report.json"
    markdown_path.write_text(str(bundle["markdown"]), encoding="utf-8")
    payload = {key: value for key, value in bundle.items() if key != "markdown"}
    json_path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return markdown_path, json_path
