"""Alerts list and the Alert Investigation Center."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from app import services
from app.ui.components import esc, html_table, page_header, panel_title, pill
from app.views import alert_table
from backend.config import load_config
from backend.rules import RuleDefinition, RuleEngine

STATUS_LABELS = {s: s.replace("_", " ").title() for s in services.ALERT_STATUSES}


def render() -> None:
    selected = st.session_state.get("selected_alert")
    if selected:
        _investigation(selected)
        return
    page_header("Security Alerts", "Prioritized findings persisted by the alert generator. Click an event to investigate.")
    severity_col, status_col, _ = st.columns([4, 4, 3])
    severities = severity_col.multiselect("Severity", ["Critical", "High", "Medium", "Low"], key="alerts-sev", placeholder="All severities")
    statuses = status_col.multiselect("Status", services.ALERT_STATUSES, key="alerts-status", placeholder="All statuses", format_func=lambda v: STATUS_LABELS[v])
    with st.container(key="panel-alerts"):
        alert_table.render("al", page_size=15, severities=severities or None, statuses=statuses or None)


def _matched_rules(event: dict) -> list[str]:
    """Re-evaluate configured rules on the stored evidence to name what actually matched."""
    engine = RuleEngine()
    for raw in load_config().get("rules", []):
        try:
            engine.add_rule(RuleDefinition(str(raw.get("rule_id", "rule")), str(raw.get("name", "rule")), str(raw.get("description", "")), bool(raw.get("enabled", True)),
                                           str(raw.get("condition", "")), float(raw.get("threshold", 0)), str(raw.get("severity", "Medium")), float(raw.get("weight", 1.0))))
        except ValueError:
            continue
    frame = pd.DataFrame([{k: (0 if v is None or (isinstance(v, float) and pd.isna(v)) else v) for k, v in event.items()}])
    names = []
    for rule in engine.rules:
        count, _ = _single(engine, rule, frame)
        if count:
            names.append(f"{rule.name} ({rule.condition})")
    return names


def _single(engine: RuleEngine, rule: RuleDefinition, frame: pd.DataFrame) -> tuple[int, float]:
    probe = RuleEngine()
    probe.add_rule(rule)
    counts, weights = probe.evaluate_frame(frame)
    return int(counts[0]), float(weights[0])


def _kv(rows: list[tuple[str, object]]) -> None:
    cells = "".join(f'<tr><td style="color:var(--muted);width:42%">{esc(k)}</td><td class="cs-mono">{esc(v) if v not in (None, "", "nan") else "—"}</td></tr>' for k, v in rows)
    st.markdown(f'<div class="cs-table-wrap"><table class="cs-table"><tbody>{cells}</tbody></table></div>', unsafe_allow_html=True)


def _investigation(alert_id: str) -> None:
    store = services.get_store()
    alert = store.get_alert(alert_id)
    if alert is None:
        st.session_state.selected_alert = None
        st.warning("That alert no longer exists.")
        return
    event = store.get_event(alert["event_key"]) if alert.get("event_key") else None
    st.button("← Back to alerts", key="inv-back", on_click=lambda: st.session_state.update(selected_alert=None))
    page_header("Alert Investigation", str(alert["event"])[:140], eyebrow="SECURITY OPERATIONS CENTER / INVESTIGATION")

    with st.container(key="panel-inv-summary"):
        panel_title("Incident summary")
        method = alert_table.detection_method(pd.Series({**(event or {}), "prediction": (event or {}).get("prediction")}))
        cols = st.columns(5)
        for column, (label, value) in zip(cols, [
            ("Severity", pill(str(alert["severity"]))), ("Risk score", f'<b style="font-size:22px">{float(alert["risk_score"]):.0f}</b> / 100'),
            ("Detection method", esc(method)), ("Timestamp", f'<span class="cs-mono">{esc(str(alert["timestamp"])[:19])}</span>'),
            ("Alert status", pill(STATUS_LABELS.get(alert["status"], alert["status"]), "accent")),
        ]):
            column.markdown(f'<div class="cs-kpi-label">{label}</div><div style="margin-top:4px">{value}</div>', unsafe_allow_html=True)

    left, right = st.columns(2)
    with left, st.container(key="panel-inv-event"):
        panel_title("Event details")
        e = event or {}
        _kv([("Source host", e.get("source_host")), ("Source IP", e.get("source_ip")), ("Destination IP", e.get("destination_ip")), ("Username", e.get("username")),
             ("Event type", e.get("event_type")), ("Action", e.get("action")), ("Protocol", e.get("protocol")), ("Port", e.get("port")), ("Source file", alert["source"]), ("Analysis run", e.get("analysis_run"))])
        if event is None:
            st.markdown('<div class="cs-sub">The underlying event is not stored; only alert-level fields are shown.</div>', unsafe_allow_html=True)
    with right, st.container(key="panel-inv-why"):
        panel_title("Why was this flagged?", "Persisted evidence; contributions are weight × component score from the fusion formula")
        if event is None:
            st.markdown(f'<div class="cs-sub">{esc(alert["explanation"])}</div>', unsafe_allow_html=True)
        else:
            weights = load_config()["model"]["weights"]
            total_w = sum(float(weights.get(k, 0)) for k in ("ml", "statistical", "rules", "context")) or 1.0
            comp = {"ML anomaly score": float(e.get("anomaly_score") or 0), "Statistical signal": float(e.get("statistical_score") or 0),
                    "Rule weight": float(e.get("rule_weight") or 0), "Context (off-hours / weekend)": float(e.get("context_score") or 0)}
            keys = {"ML anomaly score": "ml", "Statistical signal": "statistical", "Rule weight": "rules", "Context (off-hours / weekend)": "context"}
            rows = [{"signal": name, "score": f"{value:.2f}", "weight": f"{float(weights.get(keys[name], 0)) / total_w:.2f}", "contribution": f"{value * float(weights.get(keys[name], 0)) / total_w * 100:.1f}"} for name, value in comp.items()]
            html_table(pd.DataFrame(rows), severity_col=None)
            matched = _matched_rules(e)
            ml_text = "flagged anomalous" if e.get("prediction") == -1 else "not flagged"
            st.markdown(
                f'<div class="cs-sub" style="margin-top:8px">ML model ({esc(e.get("algorithm") or "n/a")}): <b>{ml_text}</b> · '
                f'Triggered rules: <b>{esc("; ".join(matched)) if matched else "none"}</b> · Failed logins in window: <b>{int(e.get("failed_login_count") or 0)}</b> · '
                f'Event rate: <b>{float(e.get("event_rate_per_min") or 0):.1f}/min</b> · Burst score: <b>{float(e.get("login_burst_score") or 0):.2f}</b> · Off-hours: <b>{"yes" if e.get("off_hours") else "no"}</b></div>'
                f'<div class="cs-panel-note" style="margin-top:8px">Contributions sum to the fused score; a failed-login-burst override can raise the final risk above that sum. '
                f'These are engineered signals, not model feature importance.</div>', unsafe_allow_html=True)
            if e.get("explanation"):
                st.markdown(f'<div class="cs-sub" style="margin-top:8px">{esc(e["explanation"])}</div>', unsafe_allow_html=True)

    with st.expander("Raw event", expanded=False):
        st.code((event or {}).get("raw_log") or alert["event"], language=None)

    with st.container(key="panel-inv-lifecycle"):
        panel_title("Alert lifecycle", "Status changes are saved to SQLite and recorded in the alert history")
        current = alert["status"] if alert["status"] in services.ALERT_STATUSES else "NEW"
        a, b, c = st.columns([3, 5, 2], vertical_alignment="bottom")
        new_status = a.selectbox("Status", services.ALERT_STATUSES, index=services.ALERT_STATUSES.index(current), format_func=lambda v: STATUS_LABELS[v], key=f"inv-status-{alert_id}")
        note = b.text_input("Analyst note (optional)", key=f"inv-note-{alert_id}")
        if c.button("Save status", key=f"inv-save-{alert_id}", type="primary", width="stretch"):
            store.update_alert_status(alert_id, new_status, user="dashboard", notes=note or None)
            services.get_audit().log("alert_status_updated", {"alert_id": alert_id, "status": new_status})
            st.rerun()
        history = pd.DataFrame(store.list_history(alert_id))
        if not history.empty:
            html_table(history.iloc[::-1][["timestamp", "action", "user", "notes"]], severity_col=None, labels={"action": "status"})
