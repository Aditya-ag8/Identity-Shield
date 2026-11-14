"""Identity Shield dashboard.

    streamlit run dashboard/app.py

Reads whatever is in the SQLite database. If the database is empty, it tells you
which two commands to run first rather than rendering an empty page.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from identity_shield import config

st.set_page_config(page_title="Identity Shield", page_icon="🛡", layout="wide")

FLAVOUR_ORDER = ["catch", "obvious", "hard", "benign"]
FLAVOUR_HELP = {
    "catch": "Round-1 rules should fire",
    "obvious": "A variant that still looks obvious",
    "hard": "Expected to be missed",
    "benign": "Normal activity; nothing should fire",
}


@st.cache_data(ttl=10)
def query(db_path: str, sql: str, params: tuple = ()) -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    try:
        return pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()


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


def main() -> None:
    st.title("Identity Shield")
    st.caption(
        "How well do AWS CloudTrail detection rules hold up when the same attack "
        "is performed in different ways?"
    )

    with st.sidebar:
        st.header("Data source")
        # Read the environment at runtime so tests can point the app at a
        # throwaway database without mutating the repository.
        default_db = os.environ.get("IDENTITY_SHIELD_DB", str(config.DEFAULT_DB))
        db_path = Path(st.text_input("Database", value=default_db, help="SQLite file"))
        ready, reason = database_ready(db_path)
        if not ready:
            st.error(reason)
            st.code(
                "python -m identity_shield.db.init --drop\n"
                "python -m identity_shield.detect.loader\n"
                "python -m identity_shield.detect.replay --ruleset baseline-v1",
                language="powershell",
            )
            st.stop()

        rulesets = query(db_path, "SELECT ruleset_version FROM ruleset ORDER BY created_at")
        if rulesets.empty:
            st.warning("No rule set has been replayed yet.")
            st.stop()
        ruleset = st.selectbox("Rule set", rulesets["ruleset_version"].tolist())

    # --- headline numbers -------------------------------------------------
    fixtures = query(db_path, "SELECT * FROM fixture")
    events = query(db_path, "SELECT COUNT(*) AS n FROM event")
    alerts = query(
        db_path,
        "SELECT COUNT(*) AS n FROM alert a JOIN rule r ON r.rule_id = a.rule_id"
        " WHERE r.ruleset_version = ?",
        (ruleset,),
    )
    rules = query(
        db_path, "SELECT * FROM rule WHERE ruleset_version = ?", (ruleset,)
    )
    compile_rows = query(
        db_path, "SELECT status FROM rule_compile WHERE ruleset_version = ?", (ruleset,)
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Fixtures", len(fixtures))
    col2.metric("Events", int(events["n"].iloc[0]))
    col3.metric("Rules", len(rules))
    col4.metric("Alerts", int(alerts["n"].iloc[0]))
    if compile_rows.empty:
        col5.metric("pySigma compile", "n/a")
    else:
        rate = (compile_rows["status"] == "pysigma").mean()
        col5.metric("pySigma compile", f"{rate:.0%}")

    tabs = st.tabs(["Fixtures", "Evasion grid", "Rules", "Compile report", "Events"])

    # --- fixtures ---------------------------------------------------------
    with tabs[0]:
        st.subheader("Fixture outcomes")
        st.caption(
            "`expected` is the contract in `fixtures/manifest.yaml`; `got` is what the "
            "selected rule set actually detected."
        )
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

    # --- evasion grid -----------------------------------------------------
    with tabs[1]:
        st.subheader("Detection by technique and variant flavour")
        grid = query(
            db_path,
            """
            SELECT f.technique_id, f.flavour,
                   CASE WHEN EXISTS (
                       SELECT 1 FROM alert a JOIN event e ON e.event_id = a.event_id
                       JOIN rule r ON r.rule_id = a.rule_id
                       WHERE e.fixture_key = f.fixture_key AND r.ruleset_version = ?
                   ) THEN 1 ELSE 0 END AS detected
            FROM fixture f
            """,
            (ruleset,),
        )
        if grid.empty:
            st.info("Nothing to plot yet.")
        else:
            pivot = (
                grid.pivot_table(index="technique_id", columns="flavour", values="detected", aggfunc="max")
                .reindex(columns=[f for f in FLAVOUR_ORDER if f in grid["flavour"].unique()])
                .fillna(-1)
            )
            figure = px.imshow(
                pivot,
                color_continuous_scale=[(0.0, "#c0392b"), (0.5, "#f39c12"), (1.0, "#27ae60")],
                zmin=0,
                zmax=1,
                aspect="auto",
                text_auto=True,
                labels={"x": "variant flavour", "y": "technique", "color": "detected"},
            )
            figure.update_layout(height=460, coloraxis_showscale=False)
            st.plotly_chart(figure, use_container_width=True)
            st.caption(
                "Green = detected, red = missed. The `hard` column is the M6 work list."
            )

    # --- rules ------------------------------------------------------------
    with tabs[2]:
        st.subheader(f"Rule set: {ruleset}")
        if rules.empty:
            st.info("No rules recorded for this rule set.")
        else:
            counts = rules.groupby("loader").size().reset_index(name="rules")
            st.dataframe(counts, hide_index=True, use_container_width=True)
            st.dataframe(
                rules[["native_id", "title", "level", "technique_id", "loader"]].sort_values(
                    ["technique_id", "native_id"]
                ),
                hide_index=True,
                use_container_width=True,
            )

    # --- compile report ---------------------------------------------------
    with tabs[3]:
        st.subheader("Sigma compile report")
        compiles = query(
            db_path,
            "SELECT path, title, status, reason FROM rule_compile WHERE ruleset_version = ?"
            " ORDER BY status, path",
            (ruleset,),
        )
        if compiles.empty:
            st.info(
                "No compile report for this rule set. Run "
                "`python -m identity_shield.detect.pysigma_backend --db ...` against the "
                "community corpus to produce one."
            )
        else:
            st.dataframe(compiles, hide_index=True, use_container_width=True)

    # --- events -----------------------------------------------------------
    with tabs[4]:
        st.subheader("Events")
        techniques = query(
            db_path,
            "SELECT DISTINCT technique_id FROM fixture ORDER BY technique_id",
        )
        choice = st.multiselect(
            "Technique", techniques["technique_id"].tolist(), default=None
        )
        sql = (
            "SELECT e.event_time, e.event_name, e.event_source, e.source_ip,"
            " e.user_agent, e.user_identity_type, f.technique_id, f.flavour"
            " FROM event e LEFT JOIN fixture f ON f.fixture_key = e.fixture_key"
        )
        params: tuple = ()
        if choice:
            placeholders = ",".join("?" for _ in choice)
            sql += f" WHERE f.technique_id IN ({placeholders})"
            params = tuple(choice)
        sql += " ORDER BY e.event_time"
        frame = query(db_path, sql, params)
        st.dataframe(frame, hide_index=True, use_container_width=True)


main()
