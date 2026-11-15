"""Report Center: exports built from persisted data with the existing report writers."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app import services
from app.ui.components import empty_state, fmt_int, page_header, panel_title
from backend import analytics
from backend.reporting import export_csv_bytes, export_pdf_bytes

MAX_EXPORT_ROWS = 100_000
REPORTS = {
    "Security Summary": "All events in scope with the severity distribution and average risk.",
    "Anomaly Report": "Only events flagged anomalous by the ML model.",
    "Alert Report": "Persisted alerts (Medium severity and above) with their lifecycle status.",
    "Event Report": "Every persisted event in scope.",
}


@st.cache_data(show_spinner=False, max_entries=8)
def _build(db_path: str, signature: tuple, kind: str, run_id: str | None) -> tuple[pd.DataFrame, int]:
    store = services.get_store()
    if kind == "Alert Report":
        frame, total = store.query_alerts(limit=MAX_EXPORT_ROWS, sort_by="risk_score")
        return frame.drop(columns=["prediction", "statistical_score", "rule_match_count", "algorithm"], errors="ignore"), total
    frame, total = store.query_events(run_id=run_id, limit=MAX_EXPORT_ROWS, sort_by="risk_score")
    if kind == "Anomaly Report":
        frame = frame[frame["prediction"] == -1]
        total = int(analytics.kpis(store, run_id)["anomalies"])
    return frame, total


def render() -> None:
    store = services.get_store()
    page_header("Report Center", "Generate exports from local records. Nothing leaves this machine.")
    latest = analytics.latest_run(store)
    if latest is None:
        empty_state("NO DATA TO REPORT", "No log data has been analyzed yet.", "Run an analysis from Monitoring first.")
        return
    with st.container(key="panel-report"):
        a, b = st.columns([4, 3])
        kind = a.segmented_control("Report", list(REPORTS), default="Security Summary", key="report-kind") or "Security Summary"
        scope = b.segmented_control("Scope", ["Latest run", "All data"], default="Latest run", key="report-scope") or "Latest run"
        st.markdown(f'<div class="cs-sub">{REPORTS[kind]}</div>', unsafe_allow_html=True)
        run_id = latest["run_id"] if scope == "Latest run" else None
        frame, total = _build(store.db_path, analytics.signature(store), kind, run_id)
        k = analytics.kpis(store, run_id)
        cols = st.columns(4)
        cols[0].metric("Records in report", fmt_int(len(frame)))
        cols[1].metric("Anomalies in scope", fmt_int(k["anomalies"]))
        cols[2].metric("Critical in scope", fmt_int(k["critical"]))
        cols[3].metric("Average risk", f"{k['avg_risk']:.1f}/100" if k["avg_risk"] is not None else "—")
        if total > len(frame):
            st.warning(f"The export is limited to the {MAX_EXPORT_ROWS:,} highest-risk records out of {total:,}.")
        if frame.empty:
            empty_state("NOTHING TO EXPORT", "This report has no records for the chosen scope.", "")
            return
        stem = kind.lower().replace(" ", "-")
        left, right, _ = st.columns([2, 2, 6])
        left.download_button("Export CSV", export_csv_bytes(frame), f"cyberspectra-{stem}.csv", "text/csv", width="stretch", key=f"csv-{stem}")
        if right.button("Generate PDF", key=f"pdf-gen-{stem}", width="stretch"):
            st.session_state[f"pdf-{stem}"] = export_pdf_bytes(frame, f"CyberSpectra {kind}")
            services.get_audit().log("report_generated", {"report": kind, "records": len(frame)})
        if st.session_state.get(f"pdf-{stem}"):
            st.download_button("Download PDF", st.session_state[f"pdf-{stem}"], f"cyberspectra-{stem}.pdf", "application/pdf", key=f"pdf-dl-{stem}")
