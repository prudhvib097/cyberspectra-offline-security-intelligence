"""SOC alert table: severity pills, search, sorting, pagination, clickable rows."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app import services
from app.ui.components import esc, paginator, pill, reset_page
from backend.analytics import STRONG_SIGNAL

SORTS = {"Newest": ("timestamp", True), "Highest risk": ("risk_score", True), "Severity": ("severity", True), "Oldest": ("timestamp", False)}
ALGORITHM_LABELS = {"isolation_forest": "Isolation Forest", "one_class_svm": "One-Class SVM"}


def detection_method(row: pd.Series) -> str:
    """Methods that actually flagged this event, from persisted evidence."""
    parts = []
    if row.get("prediction") == -1:
        parts.append(ALGORITHM_LABELS.get(str(row.get("algorithm") or "isolation_forest"), "ML anomaly"))
    if pd.notna(row.get("statistical_score")) and float(row.get("statistical_score") or 0) >= STRONG_SIGNAL:
        parts.append("Statistical")
    if pd.notna(row.get("rule_match_count")) and float(row.get("rule_match_count") or 0) > 0:
        parts.append("Rule")
    return " + ".join(parts) if parts else "Fused risk score"


def render(prefix: str, page_size: int, severities: list[str] | None = None, statuses: list[str] | None = None, show_controls: bool = True) -> None:
    store = services.get_store()
    search, sort_label = "", "Newest"
    if show_controls:
        search_col, sort_col, _ = st.columns([3, 2, 5])
        search = search_col.text_input("Search alerts", key=f"{prefix}-search", placeholder="Search event, source or alert ID", label_visibility="collapsed", on_change=reset_page, args=(prefix,))
        sort_label = sort_col.selectbox("Sort", list(SORTS), key=f"{prefix}-sort", label_visibility="collapsed", on_change=reset_page, args=(prefix,))
    sort_by, descending = SORTS[sort_label]
    offset = st.session_state.get(f"{prefix}-page", 1)
    offset = (offset - 1) * page_size
    frame, total = store.query_alerts(search=search, severities=severities, statuses=statuses, limit=page_size, offset=offset, sort_by=sort_by, descending=descending)
    if total == 0:
        from app.ui.components import empty_state

        empty_state("NO SECURITY ALERTS", "No alerts match the current view.", "Run an analysis from Monitoring, or clear the filters.")
        return
    widths = [0.9, 1.6, 4.2, 1.7, 1.9, 0.8, 1.2]
    heads = ["Severity", "Timestamp", "Event", "Source", "Detection method", "Risk", "Status"]
    with st.container(key=f"{prefix}-head"):
        for column, head in zip(st.columns(widths), heads):
            column.markdown(f'<div class="cs-rowhead">{head}</div>', unsafe_allow_html=True)
    for position, row in frame.iterrows():
        with st.container(key=f"alertrow-{prefix}-{position}"):
            cols = st.columns(widths, vertical_alignment="center")
            cols[0].markdown(pill(str(row["severity"])), unsafe_allow_html=True)
            cols[1].markdown(f'<span class="cs-mono">{esc(str(row["timestamp"])[:19])}</span>', unsafe_allow_html=True)
            label = str(row["event"])[:90] or "(no message)"
            cols[2].button(label, key=f"open-{prefix}-{position}-{row['alert_id']}", on_click=services.goto, args=("Alerts", row["alert_id"]), help="Open in the investigation center", width="stretch")
            cols[3].markdown(f'<span style="font-size:13px">{esc(row["source"])}</span>', unsafe_allow_html=True)
            cols[4].markdown(f'<span style="font-size:13px">{esc(detection_method(row))}</span>', unsafe_allow_html=True)
            cols[5].markdown(f'<b style="font-size:13px">{float(row["risk_score"]):.0f}</b>', unsafe_allow_html=True)
            cols[6].markdown(pill(str(row["status"]).replace("_", " "), "accent" if row["status"] == "NEW" else "neutral"), unsafe_allow_html=True)
    paginator(prefix, total, page_size)
