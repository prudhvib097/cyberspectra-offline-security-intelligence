from __future__ import annotations

import pandas as pd


def build_alert_feed(frame: pd.DataFrame, limit: int = 50) -> pd.DataFrame:
    if frame.empty:
        return frame.copy()
    alerts = frame[frame.get("alert_required", False)].copy()
    if alerts.empty:
        return alerts
    sort_columns = [column for column in ["severity_rank", "anomaly_score", "timestamp"] if column in alerts.columns]
    if sort_columns:
        alerts = alerts.sort_values(sort_columns, ascending=[False, False, True][: len(sort_columns)])
    return alerts.head(limit)


def alert_counts(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame(columns=["severity", "count"])
    alerts = frame[frame.get("alert_required", False)].copy()
    if alerts.empty:
        return pd.DataFrame(columns=["severity", "count"])
    return alerts.groupby("severity", dropna=False).size().reset_index(name="count")
