"""Identity Shield dashboard and control plane.

    streamlit run dashboard/app.py

Interactive Cloud Security Control Plane and empirical ATT&CK evaluation suite
over AWS CloudTrail detection rules. Supports live AWS environment connection
(Profile or STS AssumeRole), live lab resource census, capability gating,
interactive attack simulation, in-browser command console, and statistical analytics.
"""

from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from identity_shield import config
from identity_shield.analysis import outcomes
from identity_shield.contracts import VISIBLE_SETS

st.set_page_config(
    page_title="Identity Shield — Cloud Control Plane",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1rem !important;
            padding-bottom: 1rem !important;
        }
        header[data-testid="stHeader"] {
            height: 1.75rem !important;
            background: transparent !important;
        }
        h1 {
            margin-top: 0 !important;
            padding-top: 0 !important;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

FLAVOUR_ORDER = ["catch", "obvious", "hard", "benign"]
FLAVOUR_HELP = {
    "catch": "Round-1 rules should fire",
    "obvious": "A variant that still looks obvious",
    "hard": "Expected to be missed",
    "benign": "Normal activity; nothing should fire",
}

ALL_TECHNIQUES = [
    ("T1087.004", "Account Discovery: Cloud Account", "Discovery"),
    ("T1526", "Cloud Service Discovery", "Discovery"),
    ("T1580", "Cloud Infrastructure Discovery", "Discovery"),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence"),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", "Persistence"),
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access"),
    ("T1530", "Data from Cloud Storage", "Collection"),
]


@st.cache_data(ttl=15, show_spinner=False)
def query(db_path: str, sql: str, params: tuple = ()) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    try:
        return pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()


def _connect(db_path: str):
    from identity_shield.db.connection import connect

    return connect(Path(db_path))


def ensure_schema_and_rules(db_path: Path) -> None:
    """Ensure technique definitions and baseline/improved rulesets exist without injecting dummy events."""
    if not db_path.exists():
        return
    try:
        conn = _connect(str(db_path))
        try:
            from identity_shield.detect import loader, replay

            t_count = conn.execute("SELECT COUNT(*) FROM technique").fetchone()[0]
            if t_count == 0:
                loader.load_techniques(conn)
            r_count = conn.execute("SELECT COUNT(*) FROM ruleset").fetchone()[0]
            if r_count == 0:
                try:
                    replay.load_ruleset(conn, "baseline-v1")
                    replay.load_ruleset(conn, "improved-v1")
                except Exception:
                    pass
        finally:
            conn.close()
    except Exception:
        pass


@st.cache_data(ttl=15, show_spinner=False)
def summary_for(db_path: str, ruleset: str, run_id: str | None) -> dict:
    conn = _connect(db_path)
    try:
        return outcomes.summarise(conn, ruleset, run_id=run_id)
    finally:
        conn.close()


@st.cache_data(ttl=15, show_spinner=False)
def paired_for(db_path: str, baseline: str, improved: str, run_id: str | None) -> dict:
    conn = _connect(db_path)
    try:
        return outcomes.paired(conn, baseline, improved, run_id=run_id)
    finally:
        conn.close()


@st.cache_data(ttl=15, show_spinner=False)
def false_alarms_for(db_path: str, ruleset: str, run_id: str | None) -> dict:
    conn = _connect(db_path)
    try:
        return outcomes.false_alarms(conn, ruleset, run_id=run_id)
    finally:
        conn.close()


@st.cache_data(ttl=15, show_spinner=False)
def latency_for(db_path: str, ruleset: str, run_id: str | None) -> dict:
    conn = _connect(db_path)
    try:
        return outcomes.latency(conn, ruleset, run_id=run_id)
    finally:
        conn.close()


@st.cache_data(ttl=15, show_spinner=False)
def rule_diff_for(db_path: str, baseline: str, improved: str) -> dict:
    conn = _connect(db_path)
    try:
        return outcomes.rule_diff(conn, baseline, improved)
    finally:
        conn.close()


@st.cache_data(ttl=15, show_spinner=False)
def trial_frame(db_path: str, ruleset: str, run_id: str | None) -> pd.DataFrame:
    sql = """
        SELECT t.trial_id, t.run_id, t.variant_id, t.repetition,
               t.attack_succeeded, t.variant_changed, t.error,
               t.technique_id, t.technique_name, t.tactic, t.variant_set,
               t.factor_levels, t.synthetic,
               CASE WHEN EXISTS (
                   SELECT 1 FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                   WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?
               ) THEN 1 ELSE 0 END AS detected,
               (SELECT COUNT(*) FROM alert a JOIN rule r ON r.rule_id = a.rule_id
                 WHERE a.trial_id = t.trial_id AND r.ruleset_version = ?) AS alerts
        FROM v_trial_outcome t
        WHERE 1 = 1
    """
    params: list = [ruleset, ruleset]
    if run_id:
        sql += " AND t.run_id = ?"
        params.append(run_id)
    sql += " ORDER BY t.technique_id, t.variant_set, t.variant_id, t.repetition"
    frame = query(db_path, sql, tuple(params))
    if frame.empty:
        frame["valid"] = pd.Series(dtype=bool)
        return frame
    frame["factor_levels"] = frame["factor_levels"].apply(
        lambda value: json.loads(value) if isinstance(value, str) and value else {}
    )
    factors = sorted({key for levels in frame["factor_levels"] for key in levels})
    for factor in factors:
        frame[factor] = frame["factor_levels"].apply(lambda levels: levels.get(factor))
    frame["valid"] = (frame["attack_succeeded"] == 1) & (
        (frame["variant_set"] == "baseline") | (frame["variant_changed"] == 1)
    )
    return frame


def database_ready(path: Path) -> tuple[bool, str]:
    if not path.exists():
        return False, f"No database at `{path}`."
    try:
        conn = sqlite3.connect(path)
        try:
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return False, f"Database exists but is not usable: {exc}"
    return True, ""


def _pct(value: float | int | None) -> str:
    return "n/a" if value is None else f"{float(value):.1%}"


def _metric_label(row: dict) -> str:
    if row["valid"] == 0:
        return "n/a"
    return f"{_pct(row['detection_rate'])}"


def _provenance_badge(summary: dict) -> None:
    provenance = summary.get("provenance", {})
    if provenance.get("synthetic_trials") and not provenance.get("live_trials"):
        st.warning(
            "Synthetic rehearsal only: these events were derived from fixtures, "
            "not captured from AWS. The rates demonstrate the pipeline; they are "
            "not findings."
        )
    elif provenance.get("synthetic_trials"):
        st.info(
            f"{provenance['synthetic_trials']} synthetic rehearsal trial(s) are "
            "included alongside live trials. Filter by run before citing a number."
        )


def _technique_table(summary: dict) -> pd.DataFrame:
    rows = []
    for technique, entry in summary.get("techniques", {}).items():
        rows.append(
            {
                "technique": technique,
                "valid": entry["valid"],
                "detected": entry["detected"],
                "evasion": entry["evasion_rate"],
                "detection_rate": entry["detection_rate"],
                "wilson_low": entry["wilson_low"],
                "wilson_high": entry["wilson_high"],
                "alerts": entry["alerts"],
            }
        )
    return pd.DataFrame(rows)


def _factor_levels(summary: dict) -> pd.DataFrame:
    rows = []
    for factor, levels in summary.get("factor_levels", {}).items():
        for level, entry in levels.items():
            rows.append(
                {
                    "factor": factor,
                    "level": level,
                    "trials": entry["n"],
                    "detected": entry["detected"],
                    "evasion": entry["evasion_rate"],
                }
            )
    return pd.DataFrame(rows)


# ==============================================================================
# SECTION: Detection Analytics Visualizations
# ==============================================================================


def _overview(db_path: str, ruleset: str, run_id: str | None) -> None:
    summary = summary_for(db_path, ruleset, run_id)
    _provenance_badge(summary)
    overall = summary.get("overall", {"valid": 0, "detection_rate": None, "evasion_rate": None, "invalid_or_unverified": 0, "wilson_low": None, "wilson_high": None})
    false_alarms = false_alarms_for(db_path, ruleset, run_id)

    columns = st.columns(5)
    columns[0].metric("Valid attack trials", overall["valid"])
    columns[1].metric(
        "Detection",
        _pct(overall["detection_rate"]),
        help=f"Wilson 95%: {_pct(overall['wilson_low'])}–{_pct(overall['wilson_high'])}",
    )
    columns[2].metric("Evasion", _pct(overall["evasion_rate"]))
    columns[3].metric(
        "False alarms",
        _pct(false_alarms.get("rate")),
        help=f"{false_alarms.get('alerted', 0)}/{false_alarms.get('trials', 0)} benign trials alerted",
    )
    columns[4].metric("Invalid / unverified", overall["invalid_or_unverified"])

    st.caption(
        "A trial is detected when any rule in the selected set alerts on one of its "
        "events. A trial is valid when the attack verified and the captured evidence "
        "differed from the baseline; invalid trials are excluded from the denominator."
    )

    table = _technique_table(summary)
    if table.empty:
        st.info("No attack trials yet. Run a campaign from the **Simulate & Attack** tab.")
        return

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Detection by technique")
        figure = px.bar(
            table.sort_values("evasion", ascending=False),
            x="evasion",
            y="technique",
            orientation="h",
            text=table.sort_values("evasion", ascending=False)["evasion"].map(_pct),
            labels={"evasion": "evasion rate", "technique": ""},
            color="evasion",
            color_continuous_scale="RdYlGn_r",
            range_color=(0, 1),
        )
        figure.update_layout(height=max(280, 36 * len(table)), coloraxis_showscale=False)
        st.plotly_chart(figure, width="stretch")
    with right:
        st.subheader("Trial counts")
        st.dataframe(
            table[["technique", "valid", "detected", "evasion", "alerts"]].assign(
                evasion=table["evasion"].map(_pct)
            ),
            hide_index=True,
            width="stretch",
        )

    try:
        paired = paired_for(db_path, "baseline-v1", "improved-v1", run_id)
    except Exception:  # noqa: BLE001
        paired = None
    if paired and paired.get("pairs"):
        st.subheader("Round-1 to round-2")
        test = paired["mcnemar"]
        st.write(
            f"Paired trials: **{paired['pairs']}**. Baseline "
            f"**{_pct(paired['baseline_detection_rate'])}**, improved "
            f"**{_pct(paired['improved_detection_rate'])}**, delta "
            f"**{paired['delta']:+.1%}**. McNemar exact p = "
            f"**{test['p_value']:.4g}** (baseline-only {test['baseline_only']}, "
            f"improved-only {test['improved_only']})."
        )
        st.caption(
            "The test is powered for a large swing, not a few points. Read the "
            "interval and the per-technique table before claiming an improvement."
        )


def _variants(db_path: str, ruleset: str, run_id: str | None) -> None:
    frame = trial_frame(db_path, ruleset, run_id)
    if frame.empty:
        st.info("No trials in scope.")
        return
    attacks = frame[frame["variant_set"].isin(VISIBLE_SETS)].copy()
    if attacks.empty:
        st.info("No attack variants in scope. Only benign or holdout rows are present.")
        return

    techniques = sorted(attacks["technique_id"].dropna().unique())
    technique = st.selectbox("Technique", techniques, key="variant-technique")
    sets = st.multiselect(
        "Variant set",
        sorted(attacks["variant_set"].unique()),
        default=[name for name in ("baseline", "ofat", "pairwise") if name in set(attacks["variant_set"])],
        key="variant-sets",
    )
    misses_only = st.checkbox("Only valid misses", value=False)

    subset = attacks[
        (attacks["technique_id"] == technique) & (attacks["variant_set"].isin(sets))
    ].copy()
    if misses_only:
        subset = subset[subset["valid"] & (subset["detected"] == 0)]
    if subset.empty:
        st.info("No variant rows match these filters.")
        return

    factor_columns = [
        column
        for column in subset.columns
        if column
        not in {
            "factor_levels",
            "trial_id",
            "run_id",
            "variant_id",
            "repetition",
            "attack_succeeded",
            "variant_changed",
            "error",
            "technique_id",
            "technique_name",
            "tactic",
            "variant_set",
            "synthetic",
            "valid",
            "detected",
            "alerts",
        }
    ]
    subset["outcome"] = subset.apply(
        lambda row: "detected"
        if row["valid"] and row["detected"]
        else ("missed" if row["valid"] else "invalid"),
        axis=1,
    )
    display = subset[
        ["variant_id", "variant_set", *factor_columns, "outcome", "alerts", "error"]
    ].sort_values(["variant_set", "variant_id"])
    st.dataframe(display, hide_index=True, width="stretch", height=460)
    st.download_button(
        "Download this grid as CSV",
        display.to_csv(index=False).encode("utf-8"),
        file_name=f"{technique}-variants.csv",
        mime="text/csv",
    )

    st.subheader("Misses in this technique")
    missed = subset[subset["valid"] & (subset["detected"] == 0)]
    if missed.empty:
        st.success("No valid misses for the selected filters.")
    else:
        st.dataframe(
            missed[
                ["variant_id", "variant_set", *factor_columns, "error"]
            ].sort_values("variant_id"),
            hide_index=True,
            width="stretch",
        )


def _heatmap(db_path: str, ruleset: str, run_id: str | None) -> None:
    frame = trial_frame(db_path, ruleset, run_id)
    attacks = frame[
        frame["variant_set"].isin(VISIBLE_SETS) & (frame["valid"])
    ].copy()
    if attacks.empty:
        st.info("No valid attack trials in scope.")
        return
    factors = sorted(
        {
            key
            for levels in attacks["factor_levels"]
            for key in levels
        }
    )
    if not factors:
        st.info("No factor mutation columns found in recorded trials.")
        return
    factor = st.selectbox("Factor", factors, key="heatmap-factor")
    grouped = (
        attacks.groupby(["technique_id", factor], dropna=False)
        .agg(trials=("trial_id", "count"), detected=("detected", "sum"))
        .reset_index()
    )
    grouped["evasion"] = 1 - grouped["detected"] / grouped["trials"]
    pivot = grouped.pivot(index="technique_id", columns=factor, values="evasion")
    counts = grouped.pivot(index="technique_id", columns=factor, values="trials")
    if pivot.empty:
        st.info("No data for this factor.")
        return
    figure = px.imshow(
        pivot,
        color_continuous_scale="RdYlGn_r",
        zmin=0,
        zmax=1,
        aspect="auto",
        text_auto=".0%",
        labels={"x": factor, "y": "technique", "color": "evasion"},
    )
    figure.update_layout(height=max(320, 42 * len(pivot)))
    st.plotly_chart(figure, width="stretch")
    st.caption("Red = the rule set missed that level more often. Cell counts:")
    st.dataframe(counts.fillna(0).astype(int), width="stretch")


def _latency(db_path: str, ruleset: str, run_id: str | None) -> None:
    latency = latency_for(db_path, ruleset, run_id)
    st.subheader("Latency")
    if not latency.get("live"):
        st.info(
            "No live trials in scope. Ingest and delivery latency are not "
            "measured in a synthetic rehearsal; its clock would produce an artefact."
        )
        st.caption(latency.get("note", ""))
        return

    ingest = latency["ingest_lag_ms"]
    rule = latency["rule_latency_ms"]
    columns = st.columns(4)
    columns[0].metric("Ingest median", f"{ingest['median']:.0f} ms")
    columns[1].metric("Ingest p95", f"{ingest['p95']:.0f} ms")
    columns[2].metric("Replay median", f"{rule['median']:.0f} ms")
    columns[3].metric("Alerts measured", rule["n"])
    st.caption(
        "Ingest lag is CloudTrail event time to SQLite receipt. Replay latency is "
        "evaluation time, not live alert delivery; do not present it as time-to-detect."
    )
    curve = pd.DataFrame(rule.get("km_curve") or [])
    if not curve.empty:
        figure = go.Figure(
            go.Scatter(
                x=curve["t"],
                y=curve["survival"],
                mode="lines+markers",
                name="survival",
            )
        )
        figure.update_layout(
            xaxis_title="milliseconds from event to alert",
            yaxis_title="fraction not yet alerted",
            height=360,
        )
        st.plotly_chart(figure, width="stretch")


def _false_alarms(db_path: str, ruleset: str, run_id: str | None) -> None:
    st.subheader("False alarms on normal activity")
    baseline = false_alarms_for(db_path, "baseline-v1", run_id)
    improved = false_alarms_for(db_path, "improved-v1", run_id)
    columns = st.columns(2)
    for column, name, result in (
        (columns[0], "baseline-v1", baseline),
        (columns[1], "improved-v1", improved),
    ):
        column.metric(
            name,
            _pct(result.get("rate")),
            help=f"{result.get('alerted', 0)}/{result.get('trials', 0)} benign trials alerted; "
            f"Wilson {_pct(result.get('wilson_low'))}–{_pct(result.get('wilson_high'))}",
        )
    if not baseline.get("trials") and not improved.get("trials"):
        st.info("No benign trials yet. Select 'benign' variant set in Simulate & Attack tab.")
        return

    frame = trial_frame(db_path, ruleset, run_id)
    benign = frame[frame["variant_set"] == "benign"].copy()
    if not benign.empty:
        benign["outcome"] = benign["detected"].map({1: "alerted", 0: "quiet"})
        st.dataframe(
            benign[["variant_id", "technique_id", "outcome", "alerts", "error"]],
            hide_index=True,
            width="stretch",
        )


def _rule_diff(db_path: str) -> None:
    st.subheader("Round-1 versus round-2 rules")
    try:
        diff = rule_diff_for(db_path, "baseline-v1", "improved-v1")
    except Exception as exc:  # noqa: BLE001
        st.info(f"No comparison available: {exc}")
        return
    columns = st.columns(4)
    columns[0].metric("Baseline rules", diff["counts"]["baseline"])
    columns[1].metric("Improved rules", diff["counts"]["improved"])
    columns[2].metric("Added", diff["counts"]["added"])
    columns[3].metric("Removed", diff["counts"]["removed"])
    for title, rows in (
        ("Added in round 2", diff["added"]),
        ("Removed in round 2", diff["removed"]),
        ("Changed", diff["changed"]),
    ):
        st.markdown(f"**{title}**")
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        else:
            st.caption("None.")


def _lab(db_path: str, run_id: str | None) -> None:
    st.subheader("Lab runs and provenance")
    reports = sorted(config.LAB_DIR.glob("teardown-*.json"))
    if reports:
        document = json.loads(reports[-1].read_text(encoding="utf-8"))
        st.write(
            f"Latest teardown `{reports[-1].name}`: before "
            f"**{len(document.get('before', []))}**, after "
            f"**{len(document.get('after', []))}**, residue "
            f"**{len(document.get('residue', []))}**, verdict "
            f"**{'PASS' if document.get('passed') else 'FAIL'}**."
        )
    runs = query(
        db_path,
        "SELECT run_id, started_at, ended_at, region, aws_account_id, "
        "ruleset_version, synthetic, notes FROM lab_run ORDER BY started_at DESC",
    )
    if runs.empty:
        st.caption("No runs recorded in database.")
    else:
        st.dataframe(runs, hide_index=True, width="stretch")
        synthetic = int(runs["synthetic"].sum())
        st.write(f"Total: {len(runs)} run(s), **{synthetic}** synthetic.")


def _fixtures(db_path: str, ruleset: str) -> None:
    st.subheader("Fixture contract")
    summary = query(
        db_path,
        """
        SELECT f.fixture_key, f.technique_id, f.flavour,
               COALESCE(f.expected_detected, -1) AS expected,
               CASE WHEN EXISTS (
                   SELECT 1 FROM alert a JOIN event e ON e.event_id = a.event_id
                   JOIN rule r ON r.rule_id = a.rule_id
                   WHERE e.fixture_key = f.fixture_key AND r.ruleset_version = ?
               ) THEN 1 ELSE 0 END AS got,
               (SELECT GROUP_CONCAT(DISTINCT r.native_id) FROM alert a
                  JOIN event e ON e.event_id = a.event_id
                  JOIN rule r ON r.rule_id = a.rule_id
                 WHERE e.fixture_key = f.fixture_key AND r.ruleset_version = ?) AS fired_rules
        FROM fixture f
        ORDER BY f.technique_id, f.flavour
        """,
        (ruleset, ruleset),
    )
    if summary.empty:
        st.info("No fixtures registered in SQLite.")
    else:
        summary["ok"] = summary["expected"].where(summary["expected"] >= 0, None) == summary["got"]
        mismatches = summary[summary["ok"] == False]  # noqa: E712
        if mismatches.empty:
            st.success("All fixture expectations met.")
        else:
            st.error(f"{len(mismatches)} fixture expectation(s) not met.")
        st.dataframe(
            summary[["fixture_key", "technique_id", "flavour", "expected", "got", "fired_rules"]],
            width="stretch",
            hide_index=True,
        )


def _captured_events(db_path: str) -> None:
    st.subheader("Captured CloudTrail events")
    frame = query(
        db_path,
        "SELECT e.event_time, e.event_name, e.event_source, e.source_ip, "
        "e.user_agent, e.user_identity_type, e.trial_id, e.fixture_key "
        "FROM event e ORDER BY e.event_time DESC LIMIT 500",
    )
    if frame.empty:
        st.info("No events captured yet.")
    else:
        st.dataframe(frame, hide_index=True, width="stretch")
        st.caption("Limited to the 500 most recent events.")


# ==============================================================================
# MAIN APPLICATION CONTROLLER
# ==============================================================================


def main() -> None:
    st.title("Identity Shield — Cloud Security Control Plane")
    st.caption(
        "Empirical AWS CloudTrail Detection Resilience & MITRE ATT&CK Evaluation Suite."
    )

    # 1. State Initialization
    if "aws_connected" not in st.session_state:
        st.session_state["aws_connected"] = False
    if "session_info" not in st.session_state:
        st.session_state["session_info"] = {}
    if "console_history" not in st.session_state:
        st.session_state["console_history"] = []

    # 2. Sidebar Configuration
    with st.sidebar:
        st.header("Configuration")
        default_db = os.environ.get("IDENTITY_SHIELD_DB", str(config.DEFAULT_DB))
        db_path = Path(st.text_input("Database (SQLite)", value=default_db, help="Local SQLite file"))

        ready, reason = database_ready(db_path)
        if not ready:
            st.error(reason)
            st.code(
                "identity-shield init\n"
                "# or run from Command Console tab",
                language="powershell",
            )
            st.stop()

        ensure_schema_and_rules(db_path)

        # Database health counts
        st.markdown("#### Database Status")
        try:
            stat_counts = query(
                str(db_path),
                "SELECT "
                "(SELECT COUNT(*) FROM lab_run) as runs, "
                "(SELECT COUNT(*) FROM trial) as trials, "
                "(SELECT COUNT(*) FROM event) as events, "
                "(SELECT COUNT(*) FROM alert) as alerts",
            )
            c_runs = int(stat_counts["runs"][0])
            c_trials = int(stat_counts["trials"][0])
            c_events = int(stat_counts["events"][0])
            c_alerts = int(stat_counts["alerts"][0])
        except Exception:
            c_runs = c_trials = c_events = c_alerts = 0

        sc1, sc2 = st.columns(2)
        sc1.metric("Runs", c_runs)
        sc2.metric("Trials", c_trials)
        sc3, sc4 = st.columns(2)
        sc3.metric("Events", c_events)
        sc4.metric("Alerts", c_alerts)

        if c_events == 0:
            st.success("Clean Database (Zero fake/dummy data)")
        else:
            st.info(f"Telemetry active ({c_events} events)")

        if st.button("Reset Database (Wipe)", help="Reset data/identity_shield.db to 0 rows"):
            from identity_shield.db.init import init_db

            init_db(db_path, drop=True)
            ensure_schema_and_rules(db_path)
            st.success("Database wiped clean!")
            st.rerun()

        st.divider()

        # Ruleset and Run selectors
        rulesets = query(
            str(db_path), "SELECT ruleset_version FROM ruleset ORDER BY created_at"
        )
        if not rulesets.empty:
            ruleset = st.selectbox("Active Rule Set", rulesets["ruleset_version"].tolist())
        else:
            ruleset = "baseline-v1"

        runs = query(
            str(db_path),
            "SELECT run_id, synthetic, started_at FROM lab_run ORDER BY started_at DESC",
        )
        options = ["All runs"]
        labels = {"All runs": "All runs"}
        if not runs.empty:
            for row in runs.itertuples(index=False):
                provenance = "synthetic" if row.synthetic else "live"
                label = f"{row.run_id} ({provenance})"
                options.append(row.run_id)
                labels[row.run_id] = label
        chosen = st.selectbox(
            "Evaluation Run",
            options,
            format_func=lambda value: labels.get(value, value),
        )
        run_id = None if chosen == "All runs" else chosen

    # 3. Top Status Context Banner
    conn_info = st.session_state.get("session_info", {})
    if st.session_state.get("aws_connected"):
        st.success(
            f"**Connected AWS Account:** `{conn_info.get('account_id')}` | "
            f"**Region:** `{conn_info.get('region')}` | "
            f"**Org Status:** `{conn_info.get('org_status')}` | "
            f"**Caller:** `{conn_info.get('caller_arn')}`"
        )
    else:
        st.warning(
            "**AWS Cloud:** Disconnected. Connect in the **AWS Connect** tab for live lab testing, "
            "or run offline **Synthetic Rehearsals** ($0 AWS cost)."
        )

    # 4. Primary Tabs Layout
    main_tabs = st.tabs(
        [
            "AWS Connect",
            "Lab & Resources",
            "Simulate & Attack",
            "Detection Analytics",
            "Command Console",
        ]
    )

    # --------------------------------------------------------------------------
    # TAB 1: AWS Connect & Authentication
    # --------------------------------------------------------------------------
    with main_tabs[0]:
        st.header("AWS Environment Connection & Identity Integration")
        st.markdown(
            "Connect an AWS environment without disclosing permanent secrets. "
            "Supports local AWS CLI profiles and least-privilege STS AssumeRole."
        )

        auth_method = st.radio(
            "Authentication Method",
            ["AWS CLI Profile", "STS AssumeRole (Cross-Account)", "Direct Session Keys (In-Memory Only)"],
            horizontal=True,
        )

        col_reg, col_scope = st.columns(2)
        with col_reg:
            aws_region = st.selectbox(
                "AWS Region",
                ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1"],
                index=0,
            )
        with col_scope:
            deployment_scope = st.selectbox(
                "Deployment Scope",
                ["single_account", "organization"],
                help="Select organization to classify management/member hierarchy.",
            )

        profile_name = ""
        role_arn = ""
        external_id = ""
        session_name = "identity-shield-session"
        access_key = ""
        secret_key = ""
        session_token = ""

        if auth_method == "AWS CLI Profile":
            profile_name = st.text_input("Profile Name", value="default", help="Profile from ~/.aws/credentials")
        elif auth_method == "STS AssumeRole (Cross-Account)":
            role_arn = st.text_input("Role ARN", placeholder="arn:aws:iam::123456789012:role/IdentityShieldExecutionRole")
            col_ext, col_sess = st.columns(2)
            with col_ext:
                external_id = st.text_input("External ID (Optional)", placeholder="customer-guid-123")
            with col_sess:
                session_name = st.text_input("Session Name", value="identity-shield-session")
        else:
            col_ak, col_sk = st.columns(2)
            with col_ak:
                access_key = st.text_input("Access Key ID", type="password")
            with col_sk:
                secret_key = st.text_input("Secret Access Key", type="password")
            session_token = st.text_input("Session Token (Optional)", type="password")
            st.caption("Credentials reside strictly in memory for this session and are never saved to disk or database.")

        c_connect, c_disconnect = st.columns([1, 4])
        with c_connect:
            if st.button("Test & Connect", type="primary"):
                try:
                    import boto3
                    from identity_shield.lab.aws import GuardedSession
                    from identity_shield.lab.integration import DeploymentScope, assume_role, classify_account

                    if auth_method == "AWS CLI Profile":
                        boto_session = boto3.Session(profile_name=profile_name or None, region_name=aws_region)
                    elif auth_method == "STS AssumeRole (Cross-Account)":
                        base_session = boto3.Session(region_name=aws_region)
                        boto_session = assume_role(
                            base_session,
                            role_arn=role_arn,
                            external_id=external_id or None,
                            session_name=session_name,
                        )
                    else:
                        boto_session = boto3.Session(
                            aws_access_key_id=access_key or None,
                            aws_secret_access_key=secret_key or None,
                            aws_session_token=session_token or None,
                            region_name=aws_region,
                        )

                    guarded = GuardedSession(boto_session, region_name=aws_region)
                    sts_client = guarded.client("sts")
                    caller = sts_client.get_caller_identity()
                    scope_enum = (
                        DeploymentScope.ORGANIZATION
                        if deployment_scope == "organization"
                        else DeploymentScope.SINGLE_ACCOUNT
                    )
                    org_info = classify_account(boto_session, scope=scope_enum)
                    st.session_state["aws_connected"] = True
                    st.session_state["session_info"] = {
                        "account_id": caller.get("Account"),
                        "caller_arn": caller.get("Arn"),
                        "region": aws_region,
                        "org_status": getattr(org_info, "status", deployment_scope),
                    }
                    st.success("Connected to AWS environment.")
                    st.rerun()
                except Exception as exc:
                    st.session_state["aws_connected"] = False
                    st.error(f"Connection failed: {exc}")

        with c_disconnect:
            if st.button("Disconnect") and st.session_state.get("aws_connected"):
                st.session_state["aws_connected"] = False
                st.session_state["session_info"] = {}
                st.rerun()

    # --------------------------------------------------------------------------
    # TAB 2: Lab Infrastructure & Live Resource Monitor
    # --------------------------------------------------------------------------
    with main_tabs[1]:
        st.header("Lab Infrastructure & Resource Monitor")
        st.markdown(
            "Inspect and verify lab components, CloudTrail logging, S3 crown jewels, "
            "and EC2 instances in the target environment."
        )

        col_doc, col_cen = st.columns(2)
        with col_doc:
            if st.button("Run Environment Doctor", help="Verify Terraform, AWS credentials, and guardrails"):
                try:
                    import boto3
                    from identity_shield.lab.aws import GuardedSession
                    from identity_shield.lab.doctor import run_doctor

                    reg = conn_info.get("region", "us-east-1")
                    boto_sess = boto3.Session(region_name=reg)
                    session = GuardedSession(boto_sess, region_name=reg)
                    doc_report = run_doctor(session)
                    st.subheader(f"Doctor Status: {'OK' if doc_report.ok else 'FINDINGS'}")
                    check_rows = [
                        {"Check": c.name, "Status": c.status.upper(), "Detail": c.detail, "Remedy": c.remedy or ""}
                        for c in doc_report.checks
                    ]
                    st.dataframe(pd.DataFrame(check_rows), hide_index=True, width="stretch")
                except Exception as exc:
                    st.error(f"Doctor failed: {exc}")

        with col_cen:
            if st.button("Run Live Resource Census", help="Read-only enumeration of lab resources"):
                try:
                    import boto3
                    from identity_shield.lab.aws import GuardedSession
                    from identity_shield.lab.census import collect

                    reg = conn_info.get("region", "us-east-1")
                    acct = conn_info.get("account_id")
                    boto_sess = boto3.Session(region_name=reg)
                    session = GuardedSession(boto_sess, region_name=reg)
                    census_result = collect(session, region=reg, account_id=acct)
                    st.subheader(f"Discovered Resources: {len(census_result.resources)}")
                    if census_result.resources:
                        res_rows = [
                            {"Service": r.service, "Kind": r.kind, "Identifier": r.identifier, "ARN": r.arn}
                            for r in census_result.resources
                        ]
                        st.dataframe(pd.DataFrame(res_rows), hide_index=True, width="stretch")
                    else:
                        st.info("No resources with prefix 'is-' or tag 'identity-shield:lab' found in this account.")
                    if census_result.errors:
                        st.warning(f"{len(census_result.errors)} permission/service note(s)")
                except Exception as exc:
                    st.error(f"Census failed: {exc}")

        st.divider()
        st.subheader("Target Resource Configuration")
        st.caption("Configure target resource names for live testing:")
        tc1, tc2 = st.columns(2)
        with tc1:
            cfg_bucket = st.text_input("Crown Jewels S3 Bucket", value="is-data-bucket", key="cfg_bucket")
            cfg_key = st.text_input("Target S3 Object Key", value="finance/q4.csv", key="cfg_key")
            cfg_trail = st.text_input("CloudTrail Name", value="is-trail", key="cfg_trail")
        with tc2:
            cfg_queue = st.text_input("SQS Queue URL", value="https://sqs.us-east-1.amazonaws.com/123456789012/is-events", key="cfg_queue")
            cfg_instance = st.text_input("EC2 Instance ID (T1552.005)", value="", placeholder="i-0abcdef1234567890", key="cfg_instance")
            cfg_user = st.text_input("Test IAM User", value="is-test-user", key="cfg_user")

    # --------------------------------------------------------------------------
    # TAB 3: Attack Simulation & Campaign Runner
    # --------------------------------------------------------------------------
    with main_tabs[2]:
        st.header("Attack Simulation & Campaign Runner")
        st.markdown(
            "Execute ATT&CK campaigns. Choose between **Synthetic Rehearsal** (offline fixtures, $0 AWS cost) "
            "or **Live AWS Lab** against your authenticated account."
        )

        st.subheader("1. Technique Capability Matrix")
        from identity_shield.runner.capabilities import check_technique_capability

        sim_mode = st.radio("Simulation Mode", ["Synthetic Rehearsal (Offline, $0 Cost)", "Live AWS Lab Campaign"], horizontal=True)
        is_synthetic = "Synthetic" in sim_mode

        lab_cfg = {
            "data_bucket": st.session_state.get("cfg_bucket", ""),
            "instance_id": st.session_state.get("cfg_instance", ""),
            "enable_data_events": bool(st.session_state.get("cfg_bucket")),
            "enable_instance": bool(st.session_state.get("cfg_instance")),
            "test_user_name": st.session_state.get("cfg_user", "is-test-user"),
        }

        cap_rows = []
        for tech_id, name, tactic in ALL_TECHNIQUES:
            cap = check_technique_capability(tech_id, lab_cfg, synthetic=is_synthetic)
            cap_rows.append(
                {
                    "Technique": tech_id,
                    "Name": name,
                    "Tactic": tactic,
                    "Available": "YES" if cap.available else "GATED",
                    "Reason": cap.reason,
                    "Dependencies": ", ".join(cap.required_services) if cap.required_services else "offline fixture",
                }
            )
        st.dataframe(pd.DataFrame(cap_rows), hide_index=True, width="stretch")

        st.subheader("2. Launch Configuration")
        sel_techs = st.multiselect(
            "Select Techniques to Execute",
            [t[0] for t in ALL_TECHNIQUES],
            default=[t[0] for t in ALL_TECHNIQUES],
        )
        col_sets, col_reps = st.columns(2)
        with col_sets:
            sel_sets = st.multiselect("Variant Sets", ["baseline", "ofat", "pairwise", "benign"], default=["baseline", "ofat", "pairwise"])
        with col_reps:
            reps = st.slider("Repetitions", min_value=1, max_value=3, value=1)

        if not is_synthetic and not st.session_state.get("aws_connected"):
            st.warning("Live AWS Campaign requires an active connection in the 'AWS Connect' tab.")

        if st.button("Launch Campaign", type="primary"):
            cmd = [sys.executable, "-m", "identity_shield.cli", "runner", "campaign", "--db", str(db_path), "--yes"]
            if is_synthetic:
                cmd.append("--synthetic")
            for s in sel_sets:
                cmd.extend(["--set", s])
            for t in sel_techs:
                cmd.extend(["--technique", t])

            st.markdown("#### Execution Terminal Output")
            console_box = st.empty()
            with st.spinner("Executing campaign..."):
                proc = subprocess.run(cmd, capture_output=True, text=True)
                console_box.code(proc.stdout + ("\n" + proc.stderr if proc.stderr else ""), language="bash")

            with st.spinner("Replaying rulesets against newly captured telemetry..."):
                subprocess.run([sys.executable, "-m", "identity_shield.cli", "replay", "--ruleset", "baseline-v1", "--db", str(db_path)], capture_output=True)
                subprocess.run([sys.executable, "-m", "identity_shield.cli", "replay", "--ruleset", "improved-v1", "--db", str(db_path)], capture_output=True)

            st.success("Campaign execution and rule replay completed!")
            time.sleep(1)
            st.rerun()

    # --------------------------------------------------------------------------
    # TAB 4: Detection Analytics
    # --------------------------------------------------------------------------
    with main_tabs[3]:
        st.header("Detection Analytics & Rule Evaluation")
        if c_runs == 0:
            st.info(
                "No Campaign Runs Recorded Yet\n\n"
                "The database is clean and free of pre-feeded fake data. "
                "Go to **Simulate & Attack** to run a simulation or launch a quick rehearsal below."
            )
            if st.button("Run Quick Synthetic Rehearsal (T1530 S3 Exfiltration)"):
                with st.spinner("Running quick synthetic rehearsal..."):
                    cmd = [
                        sys.executable,
                        "-m",
                        "identity_shield.cli",
                        "runner",
                        "campaign",
                        "--synthetic",
                        "--yes",
                        "--technique",
                        "T1530",
                        "--db",
                        str(db_path),
                    ]
                    subprocess.run(cmd, capture_output=True)
                    subprocess.run([sys.executable, "-m", "identity_shield.cli", "replay", "--ruleset", "baseline-v1", "--db", str(db_path)], capture_output=True)
                    subprocess.run([sys.executable, "-m", "identity_shield.cli", "replay", "--ruleset", "improved-v1", "--db", str(db_path)], capture_output=True)
                st.success("Quick rehearsal complete!")
                st.rerun()
        else:
            analytics_tabs = st.tabs(
                [
                    "Overview",
                    "Variants",
                    "Evasion Heatmap",
                    "Latency",
                    "False Alarms",
                    "Rule Diff",
                    "Lab Runs",
                    "Fixtures",
                    "Captured Events",
                ]
            )
            with analytics_tabs[0]:
                _overview(str(db_path), ruleset, run_id)
            with analytics_tabs[1]:
                _variants(str(db_path), ruleset, run_id)
            with analytics_tabs[2]:
                _heatmap(str(db_path), ruleset, run_id)
            with analytics_tabs[3]:
                _latency(str(db_path), ruleset, run_id)
            with analytics_tabs[4]:
                _false_alarms(str(db_path), ruleset, run_id)
            with analytics_tabs[5]:
                _rule_diff(str(db_path))
            with analytics_tabs[6]:
                _lab(str(db_path), run_id)
            with analytics_tabs[7]:
                _fixtures(str(db_path), ruleset)
            with analytics_tabs[8]:
                _captured_events(str(db_path))

    # --------------------------------------------------------------------------
    # TAB 5: Interactive Command Console (CLI into Website)
    # --------------------------------------------------------------------------
    with main_tabs[4]:
        st.header("Interactive CLI Command Console")
        st.markdown(
            "Execute Identity Shield CLI diagnostic and operations commands directly "
            "within the web application."
        )

        st.subheader("Quick Actions")
        qa1, qa2, qa3, qa4, qa5 = st.columns(5)
        run_cmd_text = None
        if qa1.button("Lab Doctor"):
            run_cmd_text = "lab doctor"
        if qa2.button("Lab Census"):
            run_cmd_text = "lab census"
        if qa3.button("Replay Rules"):
            run_cmd_text = f"replay --ruleset {ruleset} --db {db_path}"
        if qa4.button("Preflight T1530"):
            run_cmd_text = "runner preflight --variant-id T1530-ofat-000 --synthetic"
        if qa5.button("Generate Report"):
            run_cmd_text = f"analyse report --db {db_path}"

        custom_cmd = st.text_input(
            "Execute CLI Command (`identity-shield <subcommand>`)",
            value=run_cmd_text or "",
            placeholder="e.g. runner campaign --synthetic --yes --technique T1530",
        )

        if st.button("Run Command", type="primary") and custom_cmd:
            parsed = shlex.split(custom_cmd)
            if parsed and parsed[0] == "identity-shield":
                parsed = parsed[1:]
            full_cmd = [sys.executable, "-m", "identity_shield.cli", *parsed]
            start_t = time.perf_counter()
            proc = subprocess.run(full_cmd, capture_output=True, text=True)
            elapsed = time.perf_counter() - start_t

            output_text = f"$ identity-shield {' '.join(parsed)}\n[Exit code: {proc.returncode} | Time: {elapsed:.2f}s]\n\n"
            if proc.stdout:
                output_text += proc.stdout
            if proc.stderr:
                output_text += f"\n[STDERR]:\n{proc.stderr}"

            st.session_state["console_history"].insert(0, output_text)

        if st.session_state["console_history"]:
            st.markdown("### Terminal Output")
            for entry in st.session_state["console_history"][:5]:
                st.code(entry, language="bash")
            if st.button("Clear Console History"):
                st.session_state["console_history"] = []
                st.rerun()


main()