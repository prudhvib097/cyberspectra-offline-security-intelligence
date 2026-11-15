"""Statistical anomaly detector.

Uses rolling mean / std z-scores, percentile baselines and rate-change signals
computed over each source's event timeline to produce a ``statistical_score``
in [0, 1]. With little history the detector degrades gracefully to a simple
proportional baseline instead of saturating on every long message the way the
legacy implementation did.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from backend.config import load_config

_MIN_PERIODS = 5
_ROLLING_WINDOW = 20
_Z_THRESHOLD = 2.0

_SIGNAL_WEIGHTS = {
    "failed_login_count": 0.4,
    "event_rate_per_min": 0.25,
    "message_word_count": 0.15,
    "rate_change": 0.2,
}


def _roll(group: pd.DataFrame, column: str) -> pd.Series:
    return group[column].rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS)


def _z_score(group: pd.Series, column: str) -> pd.Series:
    values = pd.to_numeric(group, errors="coerce").fillna(0.0)
    rolling_mean = values.rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS).mean()
    rolling_std = values.rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS).std()
    z = (values - rolling_mean) / (rolling_std + 1e-9)
    return _clip_pos(z, _Z_THRESHOLD)


def _clip_pos(series: pd.Series, cap: float) -> pd.Series:
    return (series.clip(lower=0.0, upper=cap) / cap).fillna(0.0)


def compute_statistical_anomaly(frame: pd.DataFrame, config: dict[str, Any] | None = None) -> pd.Series:
    """Return a per-row ``statistical_score`` in [0, 1].

    Signals are scored within each source separately so a busy web server and
    a quiet auth log are not compared against each other.
    """
    if frame.empty:
        return pd.Series(dtype=float)

    settings = config or load_config()
    signal_weights = settings.get("statistical", {}).get("signal_weights", _SIGNAL_WEIGHTS)

    working = frame.copy()
    numeric = _to_numeric_columns(working)

    sources = working.get("source_file", pd.Series([""] * len(working), index=working.index)).astype(str)

    contributions: dict[str, pd.Series] = {}
    for column, weight in signal_weights.items():
        if column == "rate_change":
            continue
        if column not in numeric.columns:
            continue
        z = _grouped_apply(numeric, sources, column, _z_score)
        scaled = _grouped_baseline(numeric, sources, column)
        contributions[column] = z * 0.6 + scaled * 0.4

    if "event_rate_per_min" in numeric.columns:
        rate = pd.to_numeric(numeric["event_rate_per_min"], errors="coerce").fillna(0.0)
        rate_smooth = rate.groupby(sources).transform(lambda values: values.rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS).mean())
        rate_change = rate_smooth.diff()
        rate_change = rate_change.clip(lower=0.0)
        baseline = rate_change.groupby(sources).transform(lambda values: values.rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS).max())
        scaled_change = (rate_change / (baseline + 1e-9)).clip(0.0, 1.0).fillna(0.0)
        contributions["rate_change"] = scaled_change

    score = pd.Series(0.0, index=frame.index, dtype=float)
    weight_sum = 0.0
    for column, weight in signal_weights.items():
        if column in contributions:
            score = score + contributions[column] * weight
            weight_sum += weight
    if weight_sum > 0:
        score = score / weight_sum

    anomaly_signal = pd.to_numeric(working.get("anomaly_score", pd.Series(0.0, index=frame.index)), errors="coerce").fillna(0.0)
    score = score * 0.7 + np.clip(anomaly_signal, 0.0, 1.0) * 0.3
    return score.clip(0.0, 1.0).rename("statistical_score")


def _to_numeric_columns(frame: pd.DataFrame) -> pd.DataFrame:
    numeric = pd.DataFrame(index=frame.index)
    for column in ["failed_login_count", "login_attempt_count", "message_word_count", "event_rate_per_min", "unique_source_ips_window", "unique_usernames_window"]:
        if column in frame.columns:
            numeric[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0)
    return numeric


def _grouped_apply(numeric: pd.DataFrame, sources: pd.Series, column: str, func) -> pd.Series:
    return numeric[column].groupby(sources).transform(lambda values: func(values, column)).fillna(0.0)


def _grouped_baseline(numeric: pd.DataFrame, sources: pd.Series, column: str) -> pd.Series:
    values = numeric[column]
    rolling_max = values.groupby(sources).transform(lambda series: series.rolling(_ROLLING_WINDOW, min_periods=_MIN_PERIODS).max())
    baseline = (values / (rolling_max + 1e-9)).clip(0.0, 1.0).fillna(0.0)
    return baseline