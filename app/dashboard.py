"""CyberSpectra: offline Security Operations Center (Streamlit entry point).

Run with:  streamlit run app/dashboard.py     (or: python main.py --dashboard)

The UI is a thin client over the canonical backend pipeline. It never invents
metrics: every number comes from SQLite rows the pipeline persisted.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app import services
from app.ui import shell
from app.ui.theme import build_css
from app.views import alerts, detection, history, monitoring, overview, reports, system

VIEWS = {
    "Overview": overview.render, "Monitoring": monitoring.render, "Detection": detection.render, "Alerts": alerts.render,
    "History": history.render, "Reports": reports.render, "System": system.render,
}


def _poll_notifications() -> None:
    """While a real watcher runs, check for new critical alerts every few seconds."""
    if services.get_monitor().status()["active"]:
        @st.fragment(run_every="5s")
        def _poll() -> None:
            if not services.get_store().new_critical_alerts().empty:
                st.rerun()

        _poll()


def main() -> None:
    st.set_page_config(page_title="CyberSpectra — Offline Security Intelligence", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
    services.init_state()
    page = st.session_state.page if st.session_state.page in VIEWS else "Overview"
    st.markdown(build_css(st.session_state.theme, page), unsafe_allow_html=True)
    services.pull_new_criticals()
    shell.render_header()
    shell.render_nav()
    shell.render_banner()
    try:
        VIEWS[page]()
    except Exception as exc:  # noqa: BLE001 - a page failure must not blank the shell
        st.error(f"The {page} page could not be displayed. The rest of the application is unaffected.")
        services.get_audit().log("page_error", {"page": page, "error": f"{type(exc).__name__}: {exc}"})
        with st.expander("Technical details (for developers)"):
            st.exception(exc)
    _poll_notifications()


main()
