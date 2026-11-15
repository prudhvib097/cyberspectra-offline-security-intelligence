"""Plotly figures. Every figure takes real data and the active theme; none invents values."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from app.ui.theme import SEVERITY_ORDER, TOKENS, severity_color

FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif'


def _base(theme: str, height: int, **layout) -> go.Figure:
    t = TOKENS[theme]
    fig = go.Figure()
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, size=12, color=t["muted"]),
        hoverlabel=dict(bgcolor=t["surface"], bordercolor=t["border2"], font=dict(family=FONT, size=13, color=t["text"])),
        legend=dict(orientation="h", y=1.12, x=0, font=dict(size=12, color=t["muted"]), bgcolor="rgba(0,0,0,0)"),
        **layout,
    )
    fig.update_xaxes(showgrid=False, linecolor=t["border"], tickfont=dict(size=12, color=t["muted"]), zeroline=False)
    fig.update_yaxes(gridcolor=t["grid"], gridwidth=1, zeroline=False, linecolor="rgba(0,0,0,0)", tickfont=dict(size=12, color=t["muted"]))
    return fig


def activity_chart(frame: pd.DataFrame, unit: str, theme: str, height: int = 280) -> go.Figure:
    t = TOKENS[theme]
    fig = _base(theme, height, hovermode="x unified")
    fmt = {"minute": "%H:%M", "hour": "%b %d %H:00", "day": "%b %d"}[unit]
    x = pd.to_datetime(frame["bucket"], errors="coerce")
    fig.add_trace(go.Scatter(x=x, y=frame["events"], name="Total events", mode="lines", line=dict(color=t["accent"], width=2), fill="tozeroy",
                             fillcolor=("rgba(10,143,152,.12)" if theme == "light" else "rgba(44,195,204,.14)"), hovertemplate="%{y:,} events"))
    fig.add_trace(go.Scatter(x=x, y=frame["anomalies"], name="Anomalies", mode="lines+markers", line=dict(color=t["high"], width=2), marker=dict(size=5), hovertemplate="%{y:,} anomalies"))
    fig.add_trace(go.Scatter(x=x, y=frame["alerts"], name="Alert-level events", mode="lines", line=dict(color=t["critical"], width=1.6, dash="dot"), hovertemplate="%{y:,} alert-level"))
    fig.update_xaxes(tickformat=fmt, nticks=8)
    return fig


def severity_bar(counts: dict[str, int], theme: str, height: int = 230) -> go.Figure:
    fig = _base(theme, height)
    names = SEVERITY_ORDER[::-1]  # plotly draws the first category at the bottom
    values = [counts.get(n, 0) for n in names]
    fig.add_trace(go.Bar(y=names, x=values, orientation="h", marker=dict(color=[severity_color(theme, n) for n in names]), text=[f"{v:,}" for v in values],
                         textposition="outside", textfont=dict(size=13, color=TOKENS[theme]["text"]), cliponaxis=False, hovertemplate="%{y}: %{x:,}<extra></extra>"))
    fig.update_xaxes(visible=False, range=[0, max(values + [1]) * 1.18])
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", tickfont=dict(size=13, color=TOKENS[theme]["text"]))
    fig.update_layout(showlegend=False, margin=dict(l=8, r=40, t=8, b=8))
    return fig


def severity_donut(counts: dict[str, int], theme: str, total_label: str, height: int = 230) -> go.Figure:
    fig = _base(theme, height)
    t = TOKENS[theme]
    total = sum(counts.get(n, 0) for n in SEVERITY_ORDER)
    fig.add_trace(go.Pie(labels=SEVERITY_ORDER, values=[counts.get(n, 0) for n in SEVERITY_ORDER], hole=0.66, sort=False, direction="clockwise",
                         marker=dict(colors=[severity_color(theme, n) for n in SEVERITY_ORDER], line=dict(color=t["surface"], width=2)), textinfo="none",
                         hovertemplate="%{label}<br>%{value:,} events · %{percent}<extra></extra>"))
    fig.add_annotation(text=f"<b>{total:,}</b><br><span style='font-size:12px;color:{t['muted']}'>{total_label}</span>", showarrow=False, font=dict(size=24, color=t["text"]))
    fig.update_layout(legend=dict(orientation="v", x=1.0, y=0.5, font=dict(size=12, color=t["text"])), margin=dict(l=8, r=8, t=8, b=8))
    return fig


def horizontal_bars(labels: list[str], values: list[int], theme: str, color: str | None = None, height: int = 230) -> go.Figure:
    t = TOKENS[theme]
    fig = _base(theme, height)
    fig.add_trace(go.Bar(y=labels[::-1], x=values[::-1], orientation="h", marker=dict(color=color or t["accent"]), text=[f"{v:,}" for v in values[::-1]], textposition="outside",
                         textfont=dict(size=13, color=t["text"]), cliponaxis=False, hovertemplate="%{y}: %{x:,}<extra></extra>"))
    fig.update_xaxes(visible=False, range=[0, max(values + [1]) * 1.2])
    fig.update_yaxes(gridcolor="rgba(0,0,0,0)", tickfont=dict(size=13, color=t["text"]))
    fig.update_layout(showlegend=False, margin=dict(l=8, r=40, t=8, b=8))
    return fig


def risk_histogram(frame: pd.DataFrame, theme: str, height: int = 230) -> go.Figure:
    t = TOKENS[theme]
    fig = _base(theme, height)
    fig.add_trace(go.Bar(x=[f"{r}<br>{s}" for r, s in zip(frame["range"], frame["severity"])], y=frame["count"], marker=dict(color=[severity_color(theme, s) for s in frame["severity"]]),
                        text=[f"{v:,}" for v in frame["count"]], textposition="outside", textfont=dict(size=13, color=t["text"]), cliponaxis=False,
                        hovertemplate="Risk %{x}: %{y:,} events<extra></extra>"))
    fig.update_xaxes(tickfont=dict(size=12, color=t["text"]))
    fig.update_yaxes(range=[0, max(frame["count"].tolist() + [1]) * 1.2])
    fig.update_layout(showlegend=False, bargap=0.25, margin=dict(l=8, r=8, t=8, b=8))
    return fig


def heatmap(matrix: pd.DataFrame, theme: str, height: int = 250) -> go.Figure:
    t = TOKENS[theme]
    fig = _base(theme, height)
    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    scale = [[0, t["surface2"]], [1, t["accent"]]]
    fig.add_trace(go.Heatmap(z=matrix.values, x=[f"{h:02d}" for h in matrix.columns], y=days, colorscale=scale, xgap=2, ygap=2, showscale=True,
                             colorbar=dict(thickness=10, len=0.9, tickfont=dict(size=11, color=t["muted"]), outlinewidth=0),
                             hovertemplate="%{y} %{x}:00 — %{z:,} events<extra></extra>"))
    fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)", tickfont=dict(size=12, color=t["text"]))
    fig.update_xaxes(title=dict(text="Hour of day", font=dict(size=12, color=t["muted"])), dtick=2)
    return fig
