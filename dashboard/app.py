"""Identity Shield dashboard.

    streamlit run dashboard/app.py

The dashboard is a read-only view over SQLite. It does not re-run attacks and
does not call AWS. Every panel states its denominator, and a synthetic
rehearsal is labelled as such wherever it appears.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from identity_shield import config
from identity_shield.analysis import outcomes
from identity_shield.contracts import VISIBLE_SETS

st.set_page_config(page_title="Identity Shield", page_icon="🛡️", layout="wide")

FLAVOUR_ORDER = ["catch", "obvious", "hard", "benign"]
FLAVOUR_HELP = {
    "catch": "Round-1 rules should fire",
    "obvious": "A variant that still looks obvious",
    "hard": "Expected to be missed",
    "benign": "Normal activity; nothing should fire",
}


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
            count = conn.execute("SELECT COUNT(*) FROM event").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return False, f"Database exists but is not usable: {exc}"
    if not count:
        return False, "Database exists but has no events."
    return True, ""


def _pct(value: float | int | None) -> str:
    return "n/a" if value is None else f"{float(value):.1%}"


def _metric_label(row: dict) -> str:
    if row["valid"] == 0:
        return "n/a"
    return f"{_pct(row['detection_rate'])}"


def _provenance_badge(summary: dict) -> None:
    provenance = summary["provenance"]
    if provenance["synthetic_trials"] and not provenance["live_trials"]:
        st.warning(
            "Synthetic rehearsal only: these events were derived from fixtures, "
            "not captured from AWS. The rates demonstrate the pipeline; they are "
            "not findings."
        )
    elif provenance["synthetic_trials"]:
        st.info(
            f"{provenance['synthetic_trials']} synthetic rehearsal trial(s) are "
            "included alongside live trials. Filter by run before citing a number."
        )


def _technique_table(summary: dict) -> pd.DataFrame:
    rows = []
    for technique, entry in summary["techniques"].items():
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
    for factor, levels in summary["factor_levels"].items():
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


def _overview(db_path: str, ruleset: str, run_id: str | None) -> None:
    summary = summary_for(db_path, ruleset, run_id)
    _provenance_badge(summary)
    overall = summary["overall"]
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
        _pct(false_alarms["rate"]),
        help=f"{false_alarms['alerted']}/{false_alarms['trials']} benign trials alerted",
    )
    columns[4].metric("Invalid / unverified", overall["invalid_or_unverified"])

    st.caption(
        "A trial is detected when any rule in the selected set alerts on one of its "
        "events. A trial is valid when the attack verified and the captured evidence "
        "differed from the baseline; invalid trials are excluded from the denominator."
    )

    table = _technique_table(summary)
    if table.empty:
        st.info("No attack trials yet. Run `identity-shield runner campaign --synthetic`.")
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
        st.plotly_chart(figure, use_container_width=True)
    with right:
        st.subheader("Trial counts")
        st.dataframe(
            table[["technique", "valid", "detected", "evasion", "alerts"]].assign(
                evasion=table["evasion"].map(_pct)
            ),
            hide_index=True,
            use_container_width=True,
        )

    try:
        paired = paired_for(db_path, "baseline-v1", "improved-v1", run_id)
    except Exception:  # noqa: BLE001 - the improved set may not be loaded
        paired = None
    if paired and paired["pairs"]:
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
    st.dataframe(display, hide_index=True, use_container_width=True, height=460)
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
            use_container_width=True,
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
    st.plotly_chart(figure, use_container_width=True)
    st.caption("Red = the rule set missed that level more often. Cell counts:")
    st.dataframe(counts.fillna(0).astype(int), use_container_width=True)
    st.write(
        "This is the attribution chart: a whole column that is red points at one "
        "factor, not at eight independent technique failures."
    )


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
        st.plotly_chart(figure, use_container_width=True)
        st.caption(
            f"Kaplan–Meier median {rule['km_median']} ms over {rule['n']} alerts. "
            "Every replay alert is treated as observed; misses are censored at the "
            "observation window in the live campaign."
        )


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
            _pct(result["rate"]),
            help=f"{result['alerted']}/{result['trials']} benign trials alerted; "
            f"Wilson {_pct(result['wilson_low'])}–{_pct(result['wilson_high'])}",
        )
    if not baseline["trials"] and not improved["trials"]:
        st.info(
            "No benign trials yet. Generate them with "
            "`identity-shield variants benign` and include `--set benign` in the campaign."
        )
        return

    frame = trial_frame(db_path, ruleset, run_id)
    benign = frame[frame["variant_set"] == "benign"].copy()
    if not benign.empty:
        benign["outcome"] = benign["detected"].map({1: "alerted", 0: "quiet"})
        st.dataframe(
            benign[["variant_id", "technique_id", "outcome", "alerts", "error"]],
            hide_index=True,
            use_container_width=True,
        )
    st.write(
        "Broadening a rule set usually raises detection and false alarms together. "
        "The improved set is not allowed to report a detection gain without this table."
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
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        else:
            st.caption("None.")
    st.caption(
        "The round-2 set intentionally replaces the naive Python rules rather than "
        "stacking on top of them, so every improvement is attributable to the new rules."
    )


def _lab(db_path: str, run_id: str | None) -> None:
    st.subheader("Lab and provenance")
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
        with st.expander("Teardown report"):
            st.json(document)
    else:
        st.info(
            "No teardown report found. A zero-residue claim is unproven until "
            "`identity-shield lab down --yes` has run against the lab account."
        )

    runs = query(
        db_path,
        "SELECT run_id, started_at, ended_at, region, aws_account_id, "
        "ruleset_version, synthetic, notes FROM lab_run ORDER BY started_at DESC",
    )
    if runs.empty:
        st.caption("No runs recorded.")
    else:
        st.dataframe(runs, hide_index=True, use_container_width=True)
        if run_id:
            st.caption(f"Filtered to `{run_id}` in the analysis tabs.")
        synthetic = int(runs["synthetic"].sum())
        st.write(
            f"{len(runs)} run(s), **{synthetic}** synthetic. Synthetic runs are "
            "written with `lab_run.synthetic = 1` and are excluded from live latency."
        )


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
        st.info("No fixtures loaded.")
    else:
        summary["ok"] = summary["expected"].where(summary["expected"] >= 0, None) == summary["got"]
        mismatches = summary[summary["ok"] == False]  # noqa: E712
        if mismatches.empty:
            st.success("All fixture expectations met.")
        else:
            st.error(f"{len(mismatches)} fixture expectation(s) not met.")
        st.dataframe(
            summary[["fixture_key", "technique_id", "flavour", "expected", "got", "fired_rules"]],
            use_container_width=True,
            hide_index=True,
        )

    st.subheader("Captured events")
    frame = query(
        db_path,
        "SELECT e.event_time, e.event_name, e.event_source, e.source_ip, "
        "e.user_agent, e.user_identity_type, e.trial_id, e.fixture_key "
        "FROM event e ORDER BY e.event_time DESC LIMIT 500",
    )
    st.dataframe(frame, hide_index=True, use_container_width=True)
    st.caption("Limited to the 500 most recent events; use SQLite for a full export.")


def main() -> None:
    st.title("Identity Shield")
    st.caption(
        "How well do AWS CloudTrail detection rules hold up when the same attack "
        "is performed in different ways?"
    )

    with st.sidebar:
        st.header("Data source")
        default_db = os.environ.get("IDENTITY_SHIELD_DB", str(config.DEFAULT_DB))
        db_path = Path(st.text_input("Database", value=default_db, help="SQLite file"))
        ready, reason = database_ready(db_path)
        if not ready:
            st.error(reason)
            st.code(
                "identity-shield demo --full\n"
                "# or, against the lab:\n"
                "identity-shield runner campaign --synthetic --yes\n"
                "identity-shield analyse report",
                language="powershell",
            )
            st.stop()

        rulesets = query(
            str(db_path), "SELECT ruleset_version FROM ruleset ORDER BY created_at"
        )
        if rulesets.empty:
            st.warning("No rule set has been replayed yet.")
            st.stop()
        ruleset = st.selectbox("Rule set", rulesets["ruleset_version"].tolist())

        runs = query(
            str(db_path),
            "SELECT run_id, synthetic, started_at FROM lab_run ORDER BY started_at DESC",
        )
        options = ["All runs"]
        labels = {"All runs": "All runs"}
        for row in runs.itertuples(index=False):
            provenance = "synthetic" if row.synthetic else "live"
            label = f"{row.run_id} ({provenance})"
            options.append(row.run_id)
            labels[row.run_id] = label
        chosen = st.selectbox(
            "Run",
            options,
            format_func=lambda value: labels.get(value, value),
        )
        run_id = None if chosen == "All runs" else chosen

        st.divider()
        st.caption(
            "Read-only. The dashboard does not call AWS or re-run attacks. "
            "Synthetic rows are labelled at the run level."
        )

    tabs = st.tabs(
        [
            "Overview",
            "Variants",
            "Evasion heatmap",
            "Latency",
            "False alarms",
            "Rule diff",
            "Lab",
            "Fixtures",
        ]
    )
    with tabs[0]:
        _overview(str(db_path), ruleset, run_id)
    with tabs[1]:
        _variants(str(db_path), ruleset, run_id)
    with tabs[2]:
        _heatmap(str(db_path), ruleset, run_id)
    with tabs[3]:
        _latency(str(db_path), ruleset, run_id)
    with tabs[4]:
        _false_alarms(str(db_path), ruleset, run_id)
    with tabs[5]:
        _rule_diff(str(db_path))
    with tabs[6]:
        _lab(str(db_path), run_id)
    with tabs[7]:
        _fixtures(str(db_path), ruleset)


main()
