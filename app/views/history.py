"""Security Event Explorer: database-side filtering, sorting and pagination."""

from __future__ import annotations

import streamlit as st

from app import services
from app.ui.components import empty_state, html_table, page_header, paginator, panel_title, reset_page

PAGE_SIZE = 25
SORTS = {"Newest": ("timestamp", True), "Oldest": ("timestamp", False), "Highest risk": ("risk_score", True), "Lowest risk": ("risk_score", False), "Severity": ("severity", True)}
COLUMNS = ["severity", "timestamp", "risk_score", "event_type", "source_ip", "source_host", "username", "source_file", "message"]


def _text(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None


def render() -> None:
    store = services.get_store()
    page_header("Event History", "Search every persisted event. Filters run in SQLite; only one page is ever loaded.")
    reset = lambda: reset_page("hist")
    with st.container(key="panel-hist-filters"):
        a, b, c = st.columns([4, 3, 3])
        search = a.text_input("Search", placeholder="Event ID, IP, host, username or message", key="hist-search", on_change=reset)
        severities = b.multiselect("Severity", ["Critical", "High", "Medium", "Low"], key="hist-sev", on_change=reset, placeholder="All")
        sort_label = c.selectbox("Sort", list(SORTS), key="hist-sort", on_change=reset)
        d, e, f, g = st.columns([3, 3, 2, 2])
        sources = d.multiselect("Source file", store.distinct_values("source_file"), key="hist-src", on_change=reset, placeholder="All")
        types = e.multiselect("Event type", store.distinct_values("event_type"), key="hist-type", on_change=reset, placeholder="All")
        date_from = f.date_input("From", value=None, key="hist-from", on_change=reset)
        date_to = g.date_input("To", value=None, key="hist-to", on_change=reset)
    sort_by, descending = SORTS[sort_label]
    page = st.session_state.get("hist-page", 1)
    frame, total = store.query_events(
        search=search, severities=severities or None, sources=sources or None, event_types=types or None,
        date_from=date_from.isoformat() if date_from else None, date_to=(date_to.isoformat() + " 23:59:59") if date_to else None,
        sort_by=sort_by, descending=descending, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE,
    )
    with st.container(key="panel-hist-table"):
        panel_title("Events", f"{total:,} matching event(s)")
        if total == 0:
            empty_state("NO MATCHING EVENTS", "No persisted events match these filters." if store.distinct_values("source_file") else "No log data has been analyzed yet.", "Adjust the filters, or run an analysis from Monitoring.")
        else:
            frame["timestamp"] = frame["timestamp"].astype(str).str.slice(0, 19)
            html_table(frame, COLUMNS, mono=["timestamp", "source_ip"], labels={"risk_score": "risk"})
            paginator("hist", total, PAGE_SIZE)
