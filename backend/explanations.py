from __future__ import annotations

from typing import Any

import pandas as pd

from backend.config import load_config
from backend.fusion import validate_weights


def build_explanations(frame: pd.DataFrame, config: dict[str, Any] | None = None) -> pd.DataFrame:
    """Generate machine-readable, human-understandable explanations.

    Works on the output of build_risk_scores() and always reflects the unified
    risk_score/severity so the explanation can never contradict other writers.
    Every detector contribution (ml, statistical, rules, context) is listed so
    reviewers can see exactly why a row received its risk score.
    """
    if frame.empty:
        return frame.copy()

    scored = frame.copy()
    settings = config or load_config()
    config_weights = settings.get("model", {}).get("weights", {})
    weights = validate_weights(config_weights)

    def explain(row: dict) -> str:
        score = float(row.get("anomaly_score", 0.0) or 0.0)
        stat = float(row.get("statistical_score", 0.0) or 0.0)
        rule_weight = float(row.get("rule_weight", 0.0) or 0.0)
        context = float(row.get("context_score", 0.0) or 0.0)
        risk = float(row.get("risk_score", 0.0) or 0.0)
        source = str(row.get("source_file", "unknown"))
        message = str(row.get("message", ""))
        rule_matches = int(row.get("rule_match_count", 0) or 0)
        burst = float(row.get("login_burst_score", 0.0) or 0.0)
        failed = int(row.get("failed_login_count", 0) or 0)
        breach_evidence = str(row.get("threshold_evidence", "") or "")

        # Per-detector contribution, scaled by the fusion weights.
        contributions = {
            "Isolation Forest/OCSVM": score * weights["ml"],
            "statistical": stat * weights["statistical"],
            "rules": rule_weight * weights["rules"],
            "context": context * weights["context"],
        }
        active = [f"{name} {value:.3f}" for name, value in sorted(contributions.items(), key=lambda item: -item[1]) if value > 0.01]

        evidence = []
        if score >= 0.6:
            evidence.append(f"Isolation Forest anomaly score {score:.2f}")
        if stat >= 0.6:
            evidence.append(f"statistical score {stat:.2f}")
        if rule_matches:
            evidence.append(f"{rule_matches} security rule(s) matched (weight {rule_weight:.2f})")
        if failed:
            evidence.append(f"{failed} failed authentication events observed")
        if burst:
            evidence.append(f"login burst score {burst:.2f}")
        if breach_evidence:
            evidence.append(f"threshold breach: {breach_evidence}")

        if risk >= 80 or rule_matches or failed >= 3:
            base = f"High-risk pattern detected in {source}: {message}."
        elif risk >= 50 or score >= 0.8 or stat >= 0.8:
            base = f"Unusual behavior in {source}: {message}."
        elif rule_matches or failed:
            base = f"Rule-flagged activity in {source}: {message}."
        else:
            base = f"Moderate activity observed in {source}: {message}."

        if active and risk >= 50:
            return f"{base} Risk score {risk:.1f}/100. Detector contributions: {'; '.join(active)}. Evidence: {'; '.join(evidence)}. Review for potential abnormal behavior."
        if evidence:
            return f"{base} Risk score {risk:.1f}/100. Evidence: {'; '.join(evidence)}. Review for potential abnormal behavior."
        return f"{base} Risk score {risk:.1f}/100. Review for potential abnormal behavior."

    needed = [c for c in ["anomaly_score", "statistical_score", "rule_weight", "context_score", "risk_score", "source_file", "message",
                          "rule_match_count", "login_burst_score", "failed_login_count", "threshold_evidence"] if c in scored.columns]
    # Plain dict records avoid per-field Series lookups (the dominant cost on large frames).
    scored["explanation"] = [explain(record) for record in scored[needed].to_dict("records")]
    scored["alert_message"] = scored["explanation"]
    return scored