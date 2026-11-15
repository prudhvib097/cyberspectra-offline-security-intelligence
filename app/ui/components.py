"""Small, theme-agnostic HTML building blocks. All styling lives in theme.py."""

from __future__ import annotations

import html
from typing import Iterable, Sequence

import pandas as pd
import streamlit as st

SHIELD_SVG = (
    '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M12 2.2 4 5.4v6c0 4.8 3.2 8.9 8 10.4 4.8-1.5 8-5.6 8-10.4v-6l-8-3.2Z" fill="var(--accent)" opacity=".16" stroke="var(--accent)" stroke-width="1.6" stroke-linejoin="round"/>'
    '<path d="m8.4 12.2 2.6 2.6 4.8-5.2" stroke="var(--accent)" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def esc(value: object) -> str:
    return html.escape("" if value is None or (isinstance(value, float) and pd.isna(value)) else str(value))


def pill(label: str, kind: str | None = None) -> str:
    kind = (kind or label).lower()
    kind = kind if kind in {"critical", "high", "medium", "low", "accent"} else "neutral"
    return f'<span class="cs-pill {kind}">{esc(label)}</span>'


def page_header(title: str, subtitle: str, eyebrow: str = "SECURITY OPERATIONS CENTER / OFFLINE") -> None:
    st.markdown(
        f'<div class="cs-eyebrow">{esc(eyebrow)}</div><div class="cs-title">{esc(title)}</div><div class="cs-sub">{esc(subtitle)}</div>',
        unsafe_allow_html=True,
    )


def panel_title(title: str, note: str = "") -> None:
    st.markdown(f'<div class="cs-panel-title">{esc(title)}</div>' + (f'<div class="cs-panel-note">{esc(note)}</div>' if note else ""), unsafe_allow_html=True)


def kpi_card(label: str, value: str, support: str, accent_var: str = "accent") -> None:
    st.markdown(
        f'<div class="cs-kpi" style="--kpi-accent:var(--{accent_var})"><div class="cs-kpi-label">{esc(label)}</div>'
        f'<div class="cs-kpi-value">{esc(value)}</div><div class="cs-kpi-support">{esc(support)}</div></div>',
        unsafe_allow_html=True,
    )


def status_strip(items: Iterable[tuple[str, str, str]]) -> None:
    """items: (label, state: ok|warn|bad|info|off, detail)."""
    parts = "".join(
        f'<span><i class="cs-dot {state if state != "off" else ""}"></i>{esc(label)} <em>{esc(detail)}</em></span>' for label, state, detail in items
    )
    st.markdown(f'<div class="cs-strip">{parts}</div>', unsafe_allow_html=True)


def empty_state(title: str = "NO SECURITY EVENTS", message: str = "No log data has been analyzed yet.", hint: str = "Upload local security logs to begin offline analysis.") -> None:
    st.markdown(f'<div class="cs-empty"><b>{esc(title)}</b>{esc(message)}<br>{esc(hint)}</div>', unsafe_allow_html=True)


def html_table(frame: pd.DataFrame, columns: Sequence[str] | None = None, severity_col: str | None = "severity", mono: Sequence[str] = (), labels: dict[str, str] | None = None) -> None:
    """Theme-aware compact table (Streamlit's canvas grid ignores our CSS tokens)."""
    if frame is None or frame.empty:
        empty_state("NO RECORDS", "Nothing matches the current view.", "")
        return
    cols = [c for c in (columns or frame.columns) if c in frame.columns]
    labels = labels or {}
    head = "".join(f"<th>{esc(labels.get(c, c.replace('_', ' ')))}</th>" for c in cols)
    body = []
    for record in frame[cols].itertuples(index=False, name=None):
        cells = []
        for column, value in zip(cols, record):
            if column == severity_col and value:
                cells.append(f"<td>{pill(str(value))}</td>")
            elif column in mono:
                cells.append(f'<td class="cs-mono">{esc(value)}</td>')
            elif isinstance(value, float):
                cells.append(f"<td>{value:,.2f}</td>" if not pd.isna(value) else "<td></td>")
            else:
                cells.append(f'<td title="{esc(value)}">{esc(value)}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    st.markdown(f'<div class="cs-table-wrap"><table class="cs-table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>', unsafe_allow_html=True)


def _step_page(key: str, delta: int) -> None:
    st.session_state[f"{key}-page"] = max(1, int(st.session_state.get(f"{key}-page", 1)) + delta)


def paginator(key: str, total: int, page_size: int) -> int:
    """Compact pager (callbacks run before the rerun, so the page shown is always current)."""
    pages = max(1, -(-total // page_size))
    current = min(int(st.session_state.get(f"{key}-page", 1)), pages)
    st.session_state[f"{key}-page"] = current
    prev_col, label_col, next_col, _ = st.columns([1, 2, 1, 6])
    prev_col.button("‹ Prev", key=f"{key}-prev", disabled=current <= 1, on_click=_step_page, args=(key, -1))
    next_col.button("Next ›", key=f"{key}-next", disabled=current >= pages, on_click=_step_page, args=(key, 1))
    label_col.markdown(f'<div class="cs-sub" style="padding-top:8px">Page {current} of {pages} · {total:,} total</div>', unsafe_allow_html=True)
    return (current - 1) * page_size


def reset_page(key: str) -> None:
    st.session_state[f"{key}-page"] = 1


def fmt_int(value: object) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return "—"
