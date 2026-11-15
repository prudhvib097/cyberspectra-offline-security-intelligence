"""Security Overview: the SOC command center."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app import services
from app.ui import charts
from app.ui.components import empty_state, fmt_int, html_table, kpi_card, page_header, panel_title, pill, status_strip
from app.ui.theme import severity_color
from app.views import alert_table
from backend import analytics
from backend.config import load_config


@st.cache_data(show_spinner=False, max_entries=48)
def _overview_data(db_path: str, signature: tuple, run_id: str | None, since: str | None) -> dict:
    store = services.get_store()
    activity, unit = analytics.activity_series(store, run_id, since)
    return {
        "kpis": analytics.kpis(store, run_id, since),
        "activity": activity, "unit": unit,
        "event_severity": analytics.severity_counts(store, run_id, since),
        "alert_severity": analytics.severity_counts(store, table="alerts"),
        "risk": analytics.risk_histogram(store, run_id, since),
        "sources": analytics.detection_sources(store, run_id, since),
        "heatmap": analytics.activity_heatmap(store, run_id, since),
        "ips": analytics.top_entities(store, "source_ip", 6, run_id, since),
        "hosts": analytics.top_entities(store, "source_host", 6, run_id, since),
        "users": analytics.top_entities(store, "username", 6, run_id, since),
    }


def _pct(part: int, whole: int) -> str:
    return f"{part / whole:.1%} of events" if whole else "no events"


def render() -> None:
    store = services.get_store()
    theme = st.session_state.theme
    latest = analytics.latest_run(store)

    head, controls = st.columns([5, 5], vertical_alignment="bottom")
    with head:
        page_header("Security Overview", "Local security telemetry, anomaly intelligence and risk posture.")
    with controls:
        scope_col, range_col = st.columns([3, 5])
        scopes = ["Latest run", "All data"]
        scope = scope_col.segmented_control("Scope", scopes, default=st.session_state.get("scope", scopes[0]), key="scope-ctl", help="Latest run = the most recent analysis; All data = everything stored in SQLite") or scopes[0]
        st.session_state.scope = scope
        range_key = range_col.segmented_control("Time range", list(analytics.TIME_RANGES), default=st.session_state.get("range", "ALL"), key="range-ctl", help="Measured back from the newest event in scope") or "ALL"
        st.session_state.range = range_key

    run_id = latest["run_id"] if (scope == "Latest run" and latest) else None
    since = analytics.since_for_range(store, range_key, run_id)

    health = services.health()
    monitor = services.get_monitor().status()
    status_strip([
        ("Offline engine", "info", "local-only processing"),
        ("System", "ok" if health["Database"][0] == "ok" else "bad", "online" if health["Database"][0] == "ok" else "degraded"),
        ("ML engine", health["ML Engine"][0], health["ML Engine"][1]),
        ("Database", health["Database"][0], health["Database"][1]),
        ("Log collector", health["Log Collector"][0], health["Log Collector"][1]),
        ("Alert engine", health["Alert Engine"][0], health["Alert Engine"][1]),
    ])

    data = _overview_data(store.db_path, analytics.signature(store), run_id, since)
    k = data["kpis"]
    if k["total"] == 0:
        st.container(border=False)
        empty_state("NO SECURITY EVENTS", "No log data has been analyzed yet." if latest is None else "No events fall in the selected scope and time range.",
                    "Upload local security logs on the Monitoring page to begin offline analysis." if latest is None else "Widen the time range or switch to All data.")
        return

    cols = st.columns(4)
    with cols[0]:
        kpi_card("Total events", fmt_int(k["total"]), f"{fmt_int(k['alert_events'])} at alert level (Medium+)", "accent")
    with cols[1]:
        kpi_card("Anomalies", fmt_int(k["anomalies"]), _pct(k["anomalies"], k["total"]) + " · ML flagged", "high")
    with cols[2]:
        kpi_card("High risk", fmt_int(k["high_risk"]), "High + Critical severity · " + _pct(k["high_risk"], k["total"]), "medium")
    with cols[3]:
        kpi_card("Critical", fmt_int(k["critical"]), _pct(k["critical"], k["total"]) + " · risk ≥ 75", "critical")

    left, right = st.columns([8, 4])
    with left, st.container(key="panel-activity"):
        panel_title("Security activity", f"Events, anomalies and alert-level events per {data['unit']}")
        if data["activity"].empty:
            empty_state("NO TIMESTAMPED EVENTS", "Events in this scope carry no valid timestamp.", "")
        else:
            st.plotly_chart(charts.activity_chart(data["activity"], data["unit"], theme), width="stretch", config={"displayModeBar": False})
    with right, st.container(key="panel-alert-severity"):
        panel_title("Alert severity", "Persisted alerts (Medium and above are alerted)")
        st.plotly_chart(charts.severity_bar(data["alert_severity"], theme), width="stretch", config={"displayModeBar": False})

    a, b, c = st.columns(3)
    with a, st.container(key="panel-composition"):
        panel_title("Severity composition", "All analyzed events in scope")
        st.plotly_chart(charts.severity_donut(data["event_severity"], theme, "events"), width="stretch", config={"displayModeBar": False})
    with b, st.container(key="panel-sources"):
        s = data["sources"]
        panel_title("Detection sources", "Signals per detector — one event can trigger several")
        shown = dict(s["signals"])
        for ml_name in ("Isolation Forest", "One-Class SVM"):
            if not shown[ml_name]:
                shown.pop(ml_name)
        if not any(n in shown for n in ("Isolation Forest", "One-Class SVM")):
            shown = {("One-Class SVM" if latest and latest.get("algorithm") == "one_class_svm" else "Isolation Forest"): 0, **shown}
        names = list(shown)
        st.plotly_chart(charts.horizontal_bars(names, [shown[n] for n in names], theme, height=190), width="stretch", config={"displayModeBar": False})
        st.markdown(f'<div class="cs-panel-note">Unique flagged events: <b>{fmt_int(s["unique_flagged"])}</b> · Alerts generated: <b>{fmt_int(s["alerts"])}</b> (signals overlap; do not add them)</div>', unsafe_allow_html=True)
    with c, st.container(key="panel-risk"):
        panel_title("Risk distribution", "Event count per risk-score band")
        st.plotly_chart(charts.risk_histogram(data["risk"], theme), width="stretch", config={"displayModeBar": False})

    posture, healthcol, heat = st.columns([3, 3, 6])
    with posture, st.container(key="panel-posture"):
        panel_title("Security posture", "Average risk of the analyzed events")
        _posture(k, data["event_severity"], theme)
    with healthcol, st.container(key="panel-health"):
        panel_title("System health", "Checked just now")
        for name, (state, detail) in health.items():
            st.markdown(f'<div style="display:flex;justify-content:space-between;font-size:13px;padding:4px 0;border-bottom:1px solid var(--border)"><span><i class="cs-dot {state}"></i>&nbsp;{name}</span><span class="cs-sub">{detail}</span></div>', unsafe_allow_html=True)
        st.markdown(f'<div class="cs-panel-note" style="margin-top:8px">Last analysis: {latest["timestamp_end"] if latest else "none"} · {fmt_int(latest["total_records"]) if latest else 0} records</div>', unsafe_allow_html=True)
    with heat, st.container(key="panel-heatmap"):
        panel_title("Security activity heatmap", "Events by weekday and hour of day")
        if data["heatmap"] is None:
            empty_state("NOT ENOUGH TIMESTAMP DATA", "A heatmap needs at least 20 timestamped events spread over 3+ hours.", "")
        else:
            st.plotly_chart(charts.heatmap(data["heatmap"], theme, height=210), width="stretch", config={"displayModeBar": False})

    ip_col, host_col, user_col = st.columns(3)
    for column, key, title, label in ((ip_col, "ips", "Top source IPs", "Source IP"), (host_col, "hosts", "Top hosts", "Host"), (user_col, "users", "Top usernames", "Username")):
        with column, st.container(key=f"panel-top-{key}"):
            panel_title(title, "Ranked by anomalies, then events")
            frame = data[key]
            if frame.empty:
                st.markdown('<div class="cs-sub">No values were extracted for this field.</div>', unsafe_allow_html=True)
            else:
                html_table(frame.rename(columns={"entity": label}), [label, "events", "anomalies", "max_risk"], severity_col=None, mono=[label], labels={"max_risk": "max risk"})

    with st.container(key="panel-recent"):
        panel_title("Recent security alerts", "Highest priority first · click an event to investigate")
        alert_table.render("ov", page_size=8, show_controls=True)


def _posture(k: dict, severity: dict, theme: str) -> None:
    avg = k["avg_risk"] or 0.0
    boundaries = load_config()["risk"]["severity_boundaries"]
    label = "Critical" if avg >= boundaries["high"] else "High" if avg >= boundaries["medium"] else "Medium" if avg >= boundaries["low"] else "Low"
    color = severity_color(theme, label)
    marker = min(100.0, max(0.0, avg))
    st.markdown(
        f'<div style="display:flex;align-items:baseline;gap:8px"><span style="font-size:32px;font-weight:750;color:{color}">{avg:.1f}</span><span class="cs-sub">/ 100 average risk</span> {pill(label)}</div>'
        f'<div style="position:relative;height:10px;border-radius:5px;margin:12px 0 4px;background:linear-gradient(90deg,var(--low) 0 25%,var(--medium) 25% 50%,var(--high) 50% 75%,var(--critical) 75% 100%)">'
        f'<div style="position:absolute;left:calc({marker}% - 2px);top:-4px;width:4px;height:18px;background:var(--text);border-radius:2px"></div></div>'
        f'<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted)"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>'
        f'<div class="cs-panel-note" style="margin-top:8px">Mean risk of the {fmt_int(k["total"])} analyzed events in scope; peak {k["max_risk"]:.1f}. Not a measure of the whole network.</div>',
        unsafe_allow_html=True,
    )
