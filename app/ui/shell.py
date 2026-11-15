"""Application shell: unified header, horizontal navigation, notifications."""

from __future__ import annotations

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from app import services
from app.ui.components import SHIELD_SVG, esc, pill


def _status_html(health: dict, monitor: dict) -> str:
    db_state = health["Database"][0]
    system = ("ok", "SYSTEM ONLINE") if db_state == "ok" else ("bad", "SYSTEM DEGRADED")
    if monitor["last_error"]:
        mon = ("bad", "MONITORING ERROR")
    elif monitor["active"]:
        mon = ("ok", "MONITORING ACTIVE")
    elif health["Log Collector"][0] == "warn":
        mon = ("warn", "MONITORING READY")
    else:
        mon = ("bad", "MONITORING UNAVAILABLE")
    items = [("info", "OFFLINE"), system, mon]
    return '<div class="cs-status">' + "".join(f'<span><i class="cs-dot {state}"></i>{label}</span>' for state, label in items) + "</div>"


def render_header() -> None:
    store = services.get_store()
    health = services.health()
    monitor = services.get_monitor().status()
    unacked = store.unacknowledged_critical_count()
    theme = st.session_state.theme
    with st.container(key="app-header"):
        brand, status, bell, theme_col = st.columns([3.1, 5.2, 0.95, 1.15], vertical_alignment="center")
        brand.markdown(
            f'<div class="cs-brand">{SHIELD_SVG}<div><div class="cs-brand-name">CYBERSPECTRA</div><div class="cs-brand-sub">Offline Security Intelligence</div></div></div>',
            unsafe_allow_html=True,
        )
        status.markdown(_status_html(health, monitor), unsafe_allow_html=True)
        with bell.popover(f"🔔 {unacked}" if unacked else "🔔", width="stretch"):
            _notification_panel(store, unacked)
        theme_col.button("☾ Dark" if theme == "light" else "☀ Light", key="theme-toggle", on_click=services.toggle_theme, width="stretch", help="Switch between light and dark theme")


def render_nav() -> None:
    with st.container(key="app-nav"):
        columns = st.columns(len(services.PAGES), gap="small")  # equal shares, no spacer: items span the full nav width
        for column, page in zip(columns, services.PAGES):
            column.button(page, key=f"nav-{page}", on_click=services.goto, args=(page,), width="stretch")


def _notification_panel(store, unacked: int) -> None:
    st.markdown(f'<div class="cs-panel-title">Notifications · {unacked} unacknowledged critical</div>', unsafe_allow_html=True)
    frame = store.list_notifications(limit=8)
    if frame.empty:
        st.markdown('<div class="cs-sub">No critical alerts have been generated.</div>', unsafe_allow_html=True)
    for position, row in enumerate(frame.itertuples(index=False)):
        acked = bool(pd.notna(row.acknowledged_at))
        st.markdown(
            f'<div style="padding:8px 0;border-bottom:1px solid var(--border)">{pill("Critical")} '
            f'<b style="font-size:13px">{esc(str(row.event)[:70])}</b><br>'
            f'<span class="cs-sub">{esc(row.timestamp)} · {esc(row.source)} · risk {row.risk_score:.0f}/100 · '
            f'{"acknowledged" if acked else "<b>unacknowledged</b>"}</span></div>',
            unsafe_allow_html=True,
        )
        view_col, ack_col = st.columns(2)
        view_col.button("Investigate", key=f"bell-inv-{position}-{row.alert_id}", on_click=services.goto, args=("Alerts", row.alert_id), width="stretch")
        ack_col.button("Acknowledge", key=f"bell-ack-{position}-{row.alert_id}", on_click=services.acknowledge, args=([row.alert_id],), disabled=acked, width="stretch")
    actions = st.columns(2)
    actions[0].button("View all alerts", key="bell-all", on_click=services.goto, args=("Alerts",), width="stretch")
    actions[1].button("Acknowledge all", key="bell-ack-all", on_click=services.acknowledge, args=(None,), disabled=unacked == 0, width="stretch")
    sound = st.checkbox("Play a sound for new critical alerts", value=services.sound_enabled(), key="sound-toggle")
    if sound != services.sound_enabled():
        services.set_sound(sound)


def render_banner() -> None:
    """Non-blocking in-app banner for newly generated critical alerts."""
    banner = st.session_state.get("banner")
    if not banner:
        return
    with st.container(key="crit-banner"):
        text, investigate, acknowledge, dismiss = st.columns([7, 1.4, 1.4, 0.7], vertical_alignment="center")
        count = banner["count"]
        text.markdown(
            f'<div class="cs-banner-title">CRITICAL SECURITY ALERT</div>'
            f'<div class="cs-banner-body"><b>{count} new critical alert{"s" if count != 1 else ""} detected</b> · '
            f'Latest event: {esc(banner["event"][:90])} · Risk Score: {banner["risk"]:.0f}/100 · Source: {esc(banner["source"])}</div>',
            unsafe_allow_html=True,
        )
        investigate.button("INVESTIGATE", key="banner-inv", type="primary", on_click=_investigate_banner, width="stretch")
        acknowledge.button("ACKNOWLEDGE", key="banner-ack", on_click=services.acknowledge, args=(banner["ids"],), width="stretch")
        dismiss.button("✕", key="banner-x", on_click=services.dismiss_banner, help="Dismiss this banner (the alert stays and the bell count is unchanged)", width="stretch")
    if st.session_state.pop("beep", False) and services.sound_enabled():
        components.html(
            "<script>try{const c=new (window.AudioContext||window.webkitAudioContext)();const o=c.createOscillator();const g=c.createGain();"
            "o.connect(g);g.connect(c.destination);o.frequency.value=880;g.gain.value=.08;o.start();setTimeout(()=>o.stop(),350);}catch(e){}</script>",
            height=0,
        )


def _investigate_banner() -> None:
    banner = st.session_state.get("banner") or {}
    services.goto("Alerts", banner.get("alert_id"))
    st.session_state.banner = None
