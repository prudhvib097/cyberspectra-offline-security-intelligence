"""Dynamic thresholds with a historical baseline and a documented fallback.

Thresholds are seeded from recent analysis history stored in SQLite when it is
available. When no history exists (fresh install, empty database) the fallback
values from ``config`` are used, and that fallback is always documented in the
result dict so reports can say which source was used.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from backend.config import load_config

DEFAULT_THRESHOLDS = {
    "event_rate_per_min_high": 30.0,
    "failed_logins_window_high": 5,
    "anomaly_score_high": 0.7,
    "risk_score_high": 60.0,
    "business_hour_start": 8,
    "business_hour_end": 18,
}


def compute_thresholds(config: dict[str, Any] | None = None, history: pd.DataFrame | None = None) -> dict[str, Any]:
    """Return effective detection thresholds.

    ``history`` is an optional DataFrame of past scored events with at least one
    of ``event_rate_per_min``, ``failed_login_count``, ``anomaly_score`` or
    ``risk_score`` columns. Percentile baselines are computed from it; missing
    signals fall back to config defaults.
    """
    settings = config or load_config()
    configured = settings.get("thresholds", {})
    fallback = {**DEFAULT_THRESHOLDS, **configured}

    thresholds = {"source": "config-fallback", **fallback}
    signal_map = {
        "event_rate_per_min_high": "event_rate_per_min",
        "failed_logins_window_high": "failed_login_count",
        "anomaly_score_high": "anomaly_score",
        "risk_score_high": "risk_score",
    }

    if history is not None and not history.empty:
        used_from_history: list[str] = []
        for threshold_key, column in signal_map.items():
            if column not in history.columns:
                continue
            values = pd.to_numeric(history[column], errors="coerce").dropna()
            if values.empty:
                continue
            baselined = float(values.quantile(0.95))
            thresholds[threshold_key] = max(baselined, 1e-6)
            used_from_history.append(column)
        if len(used_from_history) >= 2:
            thresholds["source"] = "db-history"
        elif used_from_history:
            thresholds["source"] = "partial-db-history"

    return thresholds


def load_history_thresholds(store, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Pull thresholds from the database-backed event history when possible."""
    fallback = compute_thresholds(config=config)
    if store is None:
        return fallback
    try:
        recent_events = store.list_recent_events(limit=1000)
    except Exception:
        return fallback
    if recent_events is None or recent_events.empty:
        return fallback
    return compute_thresholds(config=config, history=recent_events)


def apply_thresholds(frame: pd.DataFrame, thresholds: dict[str, Any]) -> pd.DataFrame:
    """Tag rows whose signals exceed their thresholds.

    Adds ``threshold_violation`` (0/1), ``threshold_breaches`` (count) and a
    human-readable ``threshold_evidence`` string.
    """
    if frame.empty:
        return frame.copy()

    scored = frame.copy()
    checks = [
        ("event_rate_per_min", thresholds.get("event_rate_per_min_high", DEFAULT_THRESHOLDS["event_rate_per_min_high"])),
        ("failed_login_count", thresholds.get("failed_logins_window_high", DEFAULT_THRESHOLDS["failed_logins_window_high"])),
        ("anomaly_score", thresholds.get("anomaly_score_high", DEFAULT_THRESHOLDS["anomaly_score_high"])),
        ("risk_score", thresholds.get("risk_score_high", DEFAULT_THRESHOLDS["risk_score_high"])),
    ]

    breached_columns: list[str] = []
    for column, limit in checks:
        if column not in scored.columns:
            continue
        values = pd.to_numeric(scored[column], errors="coerce").fillna(0.0)
        mask = values > limit
        breached_columns.append(column)
        scored[f"{column}_over_threshold"] = mask.astype(int)

    if breached_columns:
        scored["threshold_breaches"] = scored[[f"{column}_over_threshold" for column in breached_columns]].sum(axis=1)
    else:
        scored["threshold_breaches"] = 0
    scored["threshold_violation"] = (scored["threshold_breaches"] > 0).astype(int)

    if breached_columns:
        limits = dict(checks)
        evidence = pd.Series("", index=scored.index, dtype=object)
        for column in breached_columns:
            mask = scored[f"{column}_over_threshold"].astype(bool)
            if not mask.any():
                continue
            values = pd.to_numeric(scored.loc[mask, column], errors="coerce").fillna(0.0)
            part = column + " " + values.map("{:.1f}".format) + f" > {limits.get(column, 0)}"
            evidence.loc[mask] = np.where(evidence.loc[mask] == "", part, evidence.loc[mask] + "; " + part)
        scored["threshold_evidence"] = evidence
    else:
        scored["threshold_evidence"] = ""
    return scored
