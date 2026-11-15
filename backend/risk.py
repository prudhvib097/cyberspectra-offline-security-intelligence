from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from backend.config import DEFAULT_CONFIG, load_config
from backend.fusion import fuse_risk
from backend.rules import RuleDefinition, RuleEngine
from backend.statistical import compute_statistical_anomaly

_FALLBACK_WEIGHTS = {"ml": 0.5, "statistical": 0.2, "rules": 0.2, "context": 0.1}

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {
    "Low": "#43a047",
    "Medium": "#f9a825",
    "High": "#ef6c00",
    "Critical": "#c62828",
}


def normalize_weights(weights: dict[str, Any] | None) -> dict[str, float]:
    """Map raw config weights to the canonical ml/statistical/rules/context set.

    Legacy keys `isolation_forest`/`one_class_svm` are folded into `ml` so old
    configs keep working. The active set is scaled to sum to 1.0; weight
    validation is intentionally strict: non-numeric values are rejected and a
    zero-sum set falls back to documented defaults.
    """
    defaults = dict(_FALLBACK_WEIGHTS)
    raw = weights or {}
    normalized: dict[str, float] = {}
    for key, fallback in defaults.items():
        value = raw.get(key)
        if value is None and key == "ml":
            ml_fallback = raw.get("isolation_forest", raw.get("one_class_svm"))
            value = ml_fallback if ml_fallback is not None else fallback
        if value is None:
            value = fallback
        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Model weight {key!r} must be numeric, got {value!r}.") from exc
        if numeric < 0:
            raise ValueError(f"Model weight {key!r} must be non-negative, got {numeric}.")
        normalized[key] = numeric

    total = sum(normalized.values())
    if total <= 0:
        normalized = dict(defaults)
        total = sum(defaults.values())
    return {key: value / total for key, value in normalized.items()}


def _risk_to_severity(score: float, boundaries: dict[str, Any]) -> str:
    low = float(boundaries.get("low", 25))
    medium = float(boundaries.get("medium", 50))
    high = float(boundaries.get("high", 75))
    if score >= high:
        return "Critical"
    if score >= medium:
        return "High"
    if score >= low:
        return "Medium"
    return "Low"


def apply_severity_fields(scored: pd.DataFrame, boundaries: dict[str, Any]) -> pd.DataFrame:
    """Derive every severity-related column from risk_score (single source of truth).

    Writers must call this after risk scoring so dashboard, database, CSV and
    PDF always agree on severity, alert_required and alert_message.
    """
    if scored.empty:
        return scored

    scored["risk_score"] = pd.to_numeric(scored["risk_score"], errors="coerce").fillna(0.0).clip(0.0, 100.0)
    low = float(boundaries.get("low", 25))
    medium = float(boundaries.get("medium", 50))
    high = float(boundaries.get("high", 75))
    scored["severity"] = np.select(
        [
            scored["risk_score"] >= high,
            scored["risk_score"] >= medium,
            scored["risk_score"] >= low,
        ],
        ["Critical", "High", "Medium"],
        default="Low",
    )
    # A very large failed-login burst combined with a strong ML signal is a
    # deliberate security override: the fused score must still remain the
    # source of truth, but the rule evidence can raise a borderline result.
    failed_logins = pd.to_numeric(scored.get("failed_login_count", 0), errors="coerce").fillna(0)
    anomaly_scores = pd.to_numeric(scored.get("anomaly_score", 0), errors="coerce").fillna(0)
    critical_mask = (failed_logins >= 10) & (anomaly_scores >= 0.9)
    scored.loc[critical_mask, "risk_score"] = scored.loc[critical_mask, "risk_score"].clip(lower=high)
    scored.loc[critical_mask, "severity"] = "Critical"
    scored["severity_rank"] = scored["severity"].map({name: index + 1 for index, name in enumerate(SEVERITY_ORDER)}).fillna(1).astype(int)
    scored["severity_color"] = scored["severity"].map(SEVERITY_COLORS).fillna(SEVERITY_COLORS["Low"])
    scored["alert_required"] = scored["severity"].isin(["Medium", "High", "Critical"])
    source_files = scored.get("source_file", pd.Series("log stream", index=scored.index)).fillna("log stream").astype(str)
    scored["alert_message"] = np.where(
        scored["alert_required"],
        scored["severity"].astype(str) + " severity alert: anomaly detected in " + source_files,
        "Normal event",
    )
    return scored


def _series_column(frame: pd.DataFrame, name: str, default: int) -> pd.Series:
    column = frame.get(name)
    if column is None:
        return pd.Series(default, index=frame.index)
    return pd.to_numeric(column, errors="coerce").fillna(default).astype(int)


def build_risk_scores(frame: pd.DataFrame, config: dict[str, Any] | None = None, algorithm: str = "isolation_forest") -> pd.DataFrame:
    """Unified risk model: fuses ML, statistical, rule and context scores.

    Fusion is configurable and the weights are normalized to sum to 1.0. The
    result is a 0-100 risk_score which is the single source of truth for the
    final severity, alert_required and alert_message.
    """
    if frame.empty:
        return frame.copy()

    settings = config or load_config()
    weights = normalize_weights(settings.get("model", {}).get("weights", {}))
    boundaries = settings.get("risk", {}).get("severity_boundaries", {})

    scored = frame.copy()
    ml_score = pd.to_numeric(scored.get("anomaly_score", 0.0), errors="coerce").fillna(0.0).clip(0.0, 1.0)
    stat_score = compute_statistical_anomaly(scored)

    engine = RuleEngine()
    for raw_rule in settings.get("rules", []):
        engine.add_rule(
            RuleDefinition(
                rule_id=str(raw_rule.get("rule_id", "rule")),
                name=str(raw_rule.get("name", "rule")),
                description=str(raw_rule.get("description", "")),
                enabled=bool(raw_rule.get("enabled", True)),
                condition=str(raw_rule.get("condition", "")),
                threshold=float(raw_rule.get("threshold", 0)),
                severity=str(raw_rule.get("severity", "Medium")),
                weight=float(raw_rule.get("weight", 1.0)),
            )
        )

    if engine.rules:
        match_counts, rule_weights = engine.evaluate_frame(scored)
        scored["rule_match_count"] = match_counts
        scored["rule_weight"] = rule_weights
    else:
        scored["rule_match_count"] = 0
        scored["rule_weight"] = 0.0

    scored["statistical_score"] = stat_score

    is_business = _series_column(scored, "is_business_hours", default=1)
    is_weekend = _series_column(scored, "is_weekend", default=0)
    scored["context_score"] = ((1 - is_business) * 0.5 + is_weekend * 0.5).astype(float)

    statistical_values = pd.to_numeric(scored["statistical_score"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    rule_values = pd.to_numeric(scored["rule_weight"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    context_values = pd.to_numeric(scored["context_score"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    combined = (
        ml_score * weights["ml"]
        + statistical_values * weights["statistical"]
        + rule_values * weights["rules"]
        + context_values * weights["context"]
    )
    scored["risk_score"] = (combined.clip(0.0, 1.0) * 100.0).round(4)
    scored = apply_severity_fields(scored, boundaries)
    scored["explanation"] = (
        "Anomaly score " + pd.to_numeric(scored["anomaly_score"], errors="coerce").fillna(0).map("{:.2f}".format)
        + "; statistical score " + scored["statistical_score"].astype(float).map("{:.2f}".format)
        + "; rule matches " + scored["rule_match_count"].astype(int).astype(str)
        + "; context score " + scored["context_score"].astype(float).map("{:.2f}".format) + "."
    )
    enabled_rule_ids = [rule.rule_id for rule in engine.rules if rule.enabled]
    detectors = [algorithm] + [f"rule:{rule_id}" for rule_id in enabled_rule_ids]
    scored["detectors"] = [list(detectors) for _ in range(len(scored))]
    return scored