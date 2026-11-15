"""Detection Intelligence: model state and engineered signals, all from persisted data."""

from __future__ import annotations

import streamlit as st

from app import services
from app.ui.components import empty_state, fmt_int, html_table, kpi_card, page_header, panel_title
from backend import analytics
from backend.config import load_config
from src.feature_engineering import FEATURE_COLUMNS
import pandas as pd

ENGINE_NOTES = {
    "isolation_forest": ("Isolation Forest", "Primary anomaly detector. 100 trees; contamination = detection sensitivity."),
    "one_class_svm": ("One-Class SVM", "Alternative detector (RBF kernel, nu = detection sensitivity). Fitted on a fixed-seed sample above 20,000 rows; scores every row."),
}


def render() -> None:
    store = services.get_store()
    page_header("Detection Intelligence", "Model state and engineered behavioural signals for the most recent analysis.")
    latest = analytics.latest_run(store)
    if latest is None:
        empty_state("NO DETECTION DATA", "No analysis has been run yet.", "Run an analysis from Monitoring to populate this page.")
        return
    run_id = latest["run_id"]
    k = analytics.kpis(store, run_id)
    result = st.session_state.get("last_result")
    fit_rows = result.model_info.get("fit_rows") if result is not None and result.run_id == run_id else None

    algorithm = latest.get("algorithm") or "isolation_forest"
    name, note = ENGINE_NOTES.get(algorithm, (algorithm, ""))
    with st.container(key="panel-model"):
        panel_title(f"{name} — active engine", f"Run {run_id} · {latest.get('timestamp_end') or ''}")
        st.markdown(f'<div class="cs-sub" style="margin-bottom:8px">{note}</div>', unsafe_allow_html=True)
        cols = st.columns(5)
        normal = k["total"] - k["anomalies"]
        with cols[0]:
            kpi_card("Model state", "Fitted", "trained on this run's events", "low")
        with cols[1]:
            kpi_card("Events analyzed", fmt_int(k["total"]), f"{len(FEATURE_COLUMNS)} features each", "accent")
        with cols[2]:
            kpi_card("Normal events", fmt_int(normal), "not flagged by the model", "low")
        with cols[3]:
            kpi_card("Anomalies", fmt_int(k["anomalies"]), "flagged by the model", "high")
        with cols[4]:
            kpi_card("Anomaly rate", f"{k['anomalies'] / k['total']:.1%}" if k["total"] else "—", f"sensitivity {float(latest.get('contamination') or 0):.2f}", "medium")
        params = {"algorithm": name, "feature_count": len(FEATURE_COLUMNS), "contamination / nu": f"{float(latest.get('contamination') or 0):.2f}", "random_state": 42,
                  "training rows": fmt_int(fit_rows) if fit_rows else "all events (or not recorded for this run)"}
        if algorithm == "isolation_forest":
            params["n_estimators"] = 100
        else:
            params.update({"kernel": "rbf", "gamma": "scale"})
        html_table(pd.DataFrame([{"parameter": key, "value": value} for key, value in params.items()]), severity_col=None)
        st.markdown('<div class="cs-panel-note">No accuracy figure is shown: the logs are unlabelled, so precision/recall cannot be measured honestly.</div>', unsafe_allow_html=True)

    sig = analytics.engineered_signals(store, run_id)
    ds = analytics.detection_sources(store, run_id)
    with st.container(key="panel-signals"):
        panel_title("Detection signals", "Engineered features and detector outputs — not model feature importance")
        cols = st.columns(3)
        items = [
            ("Failed login activity", f"{fmt_int(sig['failed_events'])} events", f"peak {fmt_int(sig['max_failed'])} failures in one window"),
            ("Request / event rate", f"{sig['max_rate']:.1f}/min peak", f"mean {sig['avg_rate'] or 0:.1f}/min"),
            ("Error-keyword events", fmt_int(sig["error_events"]), "contain error / failure terms"),
            ("Unique source IPs", fmt_int(sig["unique_ips"]), f"peak {fmt_int(sig['max_ips_window'])} in one window"),
            ("Off-hours activity", fmt_int(sig["off_hours_events"]), "outside 08:00–18:59 or undated"),
            ("Burst activity", fmt_int(sig["burst_events"]), f"burst score ≥ 1.0 · peak {sig['max_burst']:.2f}"),
        ]
        for index, (label, value, support) in enumerate(items):
            with cols[index % 3]:
                kpi_card(label, value, support, "accent")
        st.markdown(
            f'<div class="cs-panel-note" style="margin-top:8px">Detector signals (overlapping): ' + " · ".join(f"{n}: {fmt_int(v)}" for n, v in ds["signals"].items() if v or n in ("Statistical Detection", "Rule Engine"))
            + f" · Unique flagged events: {fmt_int(ds['unique_flagged'])}.</div>", unsafe_allow_html=True)
