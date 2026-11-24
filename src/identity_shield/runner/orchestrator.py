"""Trial state machine.

    preflight -> execute -> verify -> collect -> diff -> cleanup -> record

The order is deliberate. Verification happens before collection so a blocked
attack is never mistaken for an evasion; cleanup is attempted even when earlier
stages fail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from identity_shield.contracts import Variant
from identity_shield.runner import diff as diff_module
from identity_shield.runner import preflight as preflight_module
from identity_shield.runner import sweeper
from identity_shield.runner.collector import CloudTrailCollector, LocalCollector, insert_events
from identity_shield.runner.executors import Executor, executor_for
from identity_shield.runner.models import (
    ExecutionResult,
    PreflightReport,
    TrialContext,
    TrialOutcome,
)
from identity_shield.runner.verifiers import verify
from identity_shield.variants.loader import Catalogue, Technique

ISO = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


_SENSITIVE_KEYS = {
    "secret_access_key",
    "stolen_secret_access_key",
    "stolen_token",
    "sessiontoken",
    "password",
}


def _redact(value: Any) -> Any:
    """Remove secret material before evidence is written to SQLite.

    The verifier needs the secret to prove the credential works. The database
    does not need it afterwards, and a lab credential in a committed report is
    still a credential leak.
    """
    if isinstance(value, Mapping):
        return {
            key: "[redacted]" if str(key).casefold() in _SENSITIVE_KEYS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def ensure_run(
    conn,
    *,
    run_id: str,
    account_id: str,
    region: str,
    ruleset_version: str,
    synthetic: bool,
    git_sha: str | None = None,
    notes: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO lab_run (run_id, started_at, aws_account_id, region, git_sha,
                             ruleset_version, synthetic, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
            synthetic=excluded.synthetic,
            notes=COALESCE(lab_run.notes, excluded.notes)
        """,
        (run_id, _now(), account_id, region, git_sha, ruleset_version, int(synthetic), notes),
    )
    conn.commit()


def _trial_id(run_id: str, variant_id: str, repetition: int) -> str:
    return f"{run_id}|{variant_id}|r{repetition}"


def _baseline_events(conn, run_id: str, technique_id: str, exclude_trial: str) -> list[dict[str, Any]]:
    row = conn.execute(
        """
        SELECT t.trial_id FROM trial t JOIN variant v ON v.variant_id = t.variant_id
        WHERE t.run_id = ? AND v.technique_id = ? AND v.variant_set = 'baseline'
          AND t.trial_id <> ?
        ORDER BY t.repetition LIMIT 1
        """,
        (run_id, technique_id, exclude_trial),
    ).fetchone()
    if not row:
        return []
    events = []
    for record in conn.execute("SELECT raw FROM event WHERE trial_id = ?", (row["trial_id"],)):
        try:
            events.append(json.loads(record["raw"]))
        except json.JSONDecodeError:
            continue
    return events


def _load_events(conn, trial_id: str) -> list[dict[str, Any]]:
    events = []
    for record in conn.execute("SELECT raw FROM event WHERE trial_id = ?", (trial_id,)):
        try:
            events.append(json.loads(record["raw"]))
        except json.JSONDecodeError:
            continue
    return events


def _record_trial(
    conn,
    *,
    trial_id: str,
    run_id: str,
    variant_id: str,
    repetition: int,
    window_start: str,
    window_end: str | None,
    attack_succeeded: bool | None,
    evidence: Mapping[str, Any],
    variant_changed: bool | None,
    variant_diff: Mapping[str, Any] | None,
    error: str | None,
) -> None:
    conn.execute(
        """
        INSERT INTO trial (trial_id, run_id, variant_id, repetition, window_start,
                           window_end, attack_succeeded, attack_evidence,
                           variant_changed, variant_diff, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(trial_id) DO UPDATE SET
            window_end=excluded.window_end,
            attack_succeeded=excluded.attack_succeeded,
            attack_evidence=excluded.attack_evidence,
            variant_changed=excluded.variant_changed,
            variant_diff=excluded.variant_diff,
            error=excluded.error
        """,
        (
            trial_id,
            run_id,
            variant_id,
            repetition,
            window_start,
            window_end,
            None if attack_succeeded is None else int(attack_succeeded),
            json.dumps(dict(evidence), sort_keys=True),
            None if variant_changed is None else int(variant_changed),
            json.dumps(dict(variant_diff or {}), sort_keys=True),
            error,
        ),
    )
    conn.commit()


@dataclass
class CampaignResult:
    run_id: str
    outcomes: list[TrialOutcome] = field(default_factory=list)
    preflight: list[PreflightReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def trials(self) -> int:
        return len(self.outcomes)

    @property
    def succeeded(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.attack_succeeded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "trials": self.trials,
            "attack_succeeded": self.succeeded,
            "errors": self.errors,
            "preflight_failures": [
                check.to_dict()
                for report in self.preflight
                for check in report.failures
            ],
        }


def run_trial(
    conn,
    ctx: TrialContext,
    *,
    executor: Executor | None = None,
    collector: Any | None = None,
    force: bool = False,
    preflight: PreflightReport | None = None,
) -> TrialOutcome:
    trial_id = _trial_id(ctx.run_id, ctx.variant.variant_id, ctx.repetition)
    existing = conn.execute(
        "SELECT attack_succeeded, error FROM trial WHERE trial_id = ?", (trial_id,)
    ).fetchone()
    if existing and not force:
        events = conn.execute(
            "SELECT COUNT(*) FROM event WHERE trial_id = ?", (trial_id,)
        ).fetchone()[0]
        return TrialOutcome(
            trial_id=trial_id,
            attack_succeeded=bool(existing["attack_succeeded"]),
            variant_changed=bool(
                conn.execute(
                    "SELECT variant_changed FROM trial WHERE trial_id = ?", (trial_id,)
                ).fetchone()[0]
            ),
            detected=False,
            alerts=0,
            events=int(events),
            error=existing["error"],
        )

    ensure_run(
        conn,
        run_id=ctx.run_id,
        account_id=ctx.account_id,
        region=ctx.region,
        ruleset_version=str(ctx.lab.get("ruleset_version") or "baseline-v1"),
        synthetic=ctx.synthetic,
        notes="synthetic rehearsal" if ctx.synthetic else None,
    )

    window_start = ctx.window_start
    report = preflight
    if report is None:
        try:
            report = preflight_module.run_preflight(ctx, clients=ctx.lab.get("clients"))
        except Exception as exc:  # noqa: BLE001
            report = PreflightReport(
                (preflight_module.PreflightCheck("preflight", "fail", str(exc)),)
            )
    if not report.ok:
        _record_trial(
            conn,
            trial_id=trial_id,
            run_id=ctx.run_id,
            variant_id=ctx.variant.variant_id,
            repetition=ctx.repetition,
            window_start=window_start,
            window_end=_now(),
            attack_succeeded=None,
            evidence={"preflight": report.to_dict()},
            variant_changed=None,
            variant_diff=None,
            error="preflight failed: "
            + "; ".join(f"{check.name}: {check.detail}" for check in report.failures),
        )
        return TrialOutcome(
            trial_id=trial_id,
            attack_succeeded=False,
            variant_changed=False,
            detected=False,
            alerts=0,
            events=0,
            error="preflight failed",
        )

    # Reserve the trial so a crash leaves evidence that it started.
    _record_trial(
        conn,
        trial_id=trial_id,
        run_id=ctx.run_id,
        variant_id=ctx.variant.variant_id,
        repetition=ctx.repetition,
        window_start=window_start,
        window_end=None,
        attack_succeeded=None,
        evidence={},
        variant_changed=None,
        variant_diff=None,
        error=None,
    )

    executor = executor or executor_for(ctx.technique.executor, synthetic=ctx.synthetic)
    result: ExecutionResult = executor.execute(ctx)
    verification = verify(ctx, result)

    expected_names = tuple(ctx.technique.event_names)
    if collector is None:
        if ctx.synthetic:
            collector = LocalCollector()
        else:
            queue_url = str(ctx.lab.get("queue_url") or "")
            if queue_url and ctx.session is not None:
                collector = CloudTrailCollector(
                    ctx.session.client("sqs", region_name=ctx.region),
                    ctx.session.client("s3", region_name=ctx.region),
                    queue_url,
                )

    collection_error = None
    events = len(result.events)
    if ctx.synthetic:
        insert_events(conn, result.events, trial_id=trial_id)
    elif collector is not None:
        window_end = _now()
        try:
            collected = collector.collect(
                conn,
                trial_id=trial_id,
                start=window_start,
                end=window_end,
                expected_event_names=expected_names,
            )
            events = collected.events
            if collected.timed_out:
                collection_error = (
                    "collection timed out; missing "
                    + ", ".join(collected.missing or ("(no expected names)",))
                )
        except Exception as exc:  # noqa: BLE001
            collection_error = f"collector: {type(exc).__name__}: {exc}"
    else:
        collection_error = "no collector configured (missing queue_url or session)"

    # Validity gate: compare with the baseline trial for this technique.
    expected_surface = tuple(
        ctx.lab.get("expected_surface")
        or ctx.variant.factor_levels.get("_expected_surface", ())
        or ()
    )
    diff: dict[str, Any] = {"expected_surface": list(expected_surface)}
    variant_changed: bool | None = None
    if ctx.variant.variant_set == "baseline":
        variant_changed = False
        diff["variant_changed"] = False
    else:
        baseline = _baseline_events(conn, ctx.run_id, ctx.variant.technique_id, trial_id)
        current = _load_events(conn, trial_id)
        if baseline and current and expected_surface:
            diff = diff_module.compare(baseline, current, expected_surface)
            variant_changed = bool(diff["variant_changed"])
        elif expected_surface:
            # No captured baseline yet (for example a single-trial run). The
            # declaration gate is all we have; record that limitation.
            diff["variant_changed"] = None
            diff["note"] = "no captured baseline available for comparison"
            variant_changed = None

    cleanup = sweeper.cleanup_actions(result.evidence)
    sweep_report = sweeper.SweepReport()
    if not ctx.synthetic and cleanup:
        sweep_report = sweeper.sweep(ctx.session, cleanup, region=ctx.region)
    residue = (
        sweeper.find_residue(ctx.session, run_id=ctx.run_id, region=ctx.region)
        if not ctx.synthetic and ctx.session is not None
        else []
    )

    error = result.error or collection_error
    if sweep_report.failed:
        error = (error + "; " if error else "") + "cleanup failed: " + json.dumps(sweep_report.failed)
    if residue:
        error = (error + "; " if error else "") + f"residue: {', '.join(residue)}"

    evidence = _redact(dict(result.evidence))
    evidence["verification"] = {
        "passed": verification.passed,
        "detail": verification.detail,
        "evidence": dict(verification.evidence),
    }
    evidence["cleanup"] = sweep_report.to_dict()
    evidence["collection"] = {"events": events, "error": collection_error}
    evidence["variant_diff"] = diff

    from identity_shield.runner.provenance import record_factor_provenance

    trial_events = _load_events(conn, trial_id) if not ctx.synthetic else result.events
    evidence["factor_provenance"] = record_factor_provenance(ctx, result, trial_events)

    _record_trial(
        conn,
        trial_id=trial_id,
        run_id=ctx.run_id,
        variant_id=ctx.variant.variant_id,
        repetition=ctx.repetition,
        window_start=window_start,
        window_end=_now(),
        attack_succeeded=verification.passed,
        evidence=evidence,
        variant_changed=variant_changed,
        variant_diff=diff,
        error=error,
    )

    detection = conn.execute(
        """
        SELECT COUNT(*) AS alerts FROM alert WHERE trial_id = ?
        """,
        (trial_id,),
    ).fetchone()
    return TrialOutcome(
        trial_id=trial_id,
        attack_succeeded=verification.passed,
        variant_changed=bool(variant_changed),
        detected=bool(detection["alerts"]),
        alerts=int(detection["alerts"]),
        events=events,
        error=error,
        evidence=evidence,
    )


def run_campaign(
    conn,
    *,
    run_id: str,
    variants: Sequence[Variant],
    catalogue: Catalogue,
    account_id: str,
    region: str,
    repetitions: int = 1,
    synthetic: bool = False,
    session: Any = None,
    lab: Mapping[str, Any] | None = None,
    force: bool = False,
) -> CampaignResult:
    """Run every variant, baselines first so the validity diff has a reference."""
    ensure_run(
        conn,
        run_id=run_id,
        account_id=account_id,
        region=region,
        ruleset_version=str((lab or {}).get("ruleset_version") or "baseline-v1"),
        synthetic=synthetic,
        notes="synthetic rehearsal" if synthetic else None,
    )
    result = CampaignResult(run_id=run_id)
    ordered = sorted(
        variants,
        key=lambda variant: (
            variant.technique_id,
            0 if variant.variant_set == "baseline" else 1,
            variant.variant_set,
            variant.variant_id,
        ),
    )
    for variant in ordered:
        technique = catalogue.technique(variant.technique_id)
        for repetition in range(1, repetitions + 1):
            expected_surface = (
                catalogue.expected_surface(technique, variant.factor_levels)
                if variant.variant_set not in {"baseline", "benign"}
                else ()
            )
            trial_lab = dict(lab or {})
            trial_lab["expected_surface"] = expected_surface
            if synthetic:
                trial_lab["clients"] = {}
            ctx = TrialContext(
                run_id=run_id,
                variant=variant,
                technique=technique,
                repetition=repetition,
                account_id=account_id,
                region=region,
                lab=trial_lab,
                synthetic=synthetic,
                session=session,
            )
            try:
                outcome = run_trial(conn, ctx, force=force)
            except Exception as exc:  # noqa: BLE001 - a single trial must not kill the campaign
                result.errors.append(
                    f"{variant.variant_id} r{repetition}: {type(exc).__name__}: {exc}"
                )
                continue
            result.outcomes.append(outcome)
            if outcome.error:
                result.errors.append(f"{variant.variant_id} r{repetition}: {outcome.error}")
    conn.execute(
        "UPDATE lab_run SET ended_at = ? WHERE run_id = ?", (_now(), run_id)
    )
    conn.commit()
    return result
