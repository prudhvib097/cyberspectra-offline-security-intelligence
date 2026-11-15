"""Weighted detector fusion into a single 0-100 risk score.

The fusion is the ONLY place the per-detector weights are applied, so risk
scores stay identical across every interface (CLI, dashboard, watcher, reports).
"""

from __future__ import annotations

from typing import Any

FUSION_KEYS = ("ml", "statistical", "rules", "context")
FALLBACK_WEIGHTS: dict[str, float] = {"ml": 0.5, "statistical": 0.2, "rules": 0.2, "context": 0.1}


def validate_weights(weights: dict[str, Any] | None) -> dict[str, float]:
    """Validate a weights map; scale it to sum 1.0; fall back on bad input."""
    if not weights:
        return dict(FALLBACK_WEIGHTS)
    validated: dict[str, float] = {}
    for key in FUSION_KEYS:
        value = weights.get(key, FALLBACK_WEIGHTS[key])
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = FALLBACK_WEIGHTS[key]
        validated[key] = max(0.0, value)
    total = sum(validated.values())
    if total <= 0:
        return dict(FALLBACK_WEIGHTS)
    return {key: value / total for key, value in validated.items()}


def fuse_risk(ml: float, statistical: float, rules: float, context: float, weights: dict[str, Any] | None = None) -> float:
    """Combine the four detector scores (each in [0, 1]) into one risk in [0, 100]."""
    normalized = validate_weights(weights)
    combined = (
        max(0.0, min(1.0, ml)) * normalized["ml"]
        + max(0.0, min(1.0, statistical)) * normalized["statistical"]
        + max(0.0, min(1.0, rules)) * normalized["rules"]
        + max(0.0, min(1.0, context)) * normalized["context"]
    )
    return round(combined * 100.0, 4)