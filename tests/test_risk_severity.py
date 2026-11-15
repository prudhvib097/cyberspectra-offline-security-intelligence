from __future__ import annotations

import pandas as pd
import pytest

from backend.config import DEFAULT_CONFIG
from backend.risk import build_risk_scores, normalize_weights


def _scored_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "message": "Failed password for admin from 192.168.1.20",
                "raw_line": "Failed password for admin from 192.168.1.20",
                "source_file": "auth.log",
                "source": "auth.log",
                "line_number": 1,
                "anomaly_score": 0.95,
                "failed_login_count": 37,
                "login_attempt_count": 37,
                "successful_login_count": 0,
                "failed_login_ratio": 1.0,
                "login_burst_score": 1.0,
                "message_word_count": 8,
                "is_business_hours": 1,
                "is_weekend": 0,
                "prediction": -1,
                "timestamp": "2026-05-01 10:00:00",
            },
            {
                "message": "Accepted password for analyst",
                "raw_line": "Accepted password for analyst",
                "source_file": "auth.log",
                "source": "auth.log",
                "line_number": 2,
                "anomaly_score": 0.05,
                "failed_login_count": 0,
                "login_attempt_count": 1,
                "successful_login_count": 1,
                "failed_login_ratio": 0.0,
                "login_burst_score": 0.0,
                "message_word_count": 4,
                "is_business_hours": 1,
                "is_weekend": 0,
                "prediction": 1,
                "timestamp": "2026-05-01 10:00:01",
            },
        ]
    )


def test_risk_is_single_source_of_truth() -> None:
    scored = build_risk_scores(_scored_frame(), config=DEFAULT_CONFIG)
    for _, row in scored.iterrows():
        boundary_map = DEFAULT_CONFIG["risk"]["severity_boundaries"]
        expected = _mapped_severity(row["risk_score"], boundary_map)
        assert row["severity"] == expected
        assert row["alert_required"] == (expected in ["Medium", "High", "Critical"])
        assert row["severity_rank"] == {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}[expected]
        assert "severity alert" in row["alert_message"] if row["alert_required"] else row["alert_message"] == "Normal event"


def _mapped_severity(risk_score: float, boundaries: dict) -> str:
    if risk_score >= float(boundaries["high"]):
        return "Critical"
    if risk_score >= float(boundaries["medium"]):
        return "High"
    if risk_score >= float(boundaries["low"]):
        return "Medium"
    return "Low"


def test_bruteforce_rule_triggers_in_pipeline() -> None:
    scored = build_risk_scores(_scored_frame(), config=DEFAULT_CONFIG)
    brute = scored.iloc[0]
    assert brute["rule_match_count"] == 1
    assert brute["rule_weight"] >= 1.0
    assert brute["severity"] == "Critical"


def test_normal_event_stays_low() -> None:
    scored = build_risk_scores(_scored_frame(), config=DEFAULT_CONFIG)
    normal = scored.iloc[1]
    assert normal["rule_match_count"] == 0
    assert normal["severity"] == "Low"
    assert not normal["alert_required"]
    assert normal["risk_score"] < 25


def test_risk_explanation_and_alert_message_consistent() -> None:
    scored = build_risk_scores(_scored_frame(), config=DEFAULT_CONFIG)
    assert scored.iloc[0]["risk_score"] > 0
    assert scored.iloc[0]["alert_message"].startswith("Critical severity alert")


def test_weights_normalize_to_one() -> None:
    assert normalize_weights(None) == {"ml": 0.5, "statistical": 0.2, "rules": 0.2, "context": 0.1}
    result = normalize_weights({"ml": 1.0, "statistical": 1.0, "rules": 1.0, "context": 1.0})
    assert sum(result.values()) == pytest.approx(1.0)
    legacy = normalize_weights({"isolation_forest": 0.7, "statistical": 0.3})
    assert legacy["ml"] == pytest.approx(0.7 / 1.3, abs=1e-9)
    assert legacy["statistical"] == pytest.approx(0.3 / 1.3, abs=1e-9)
    assert sum(legacy.values()) == pytest.approx(1.0)


def test_weights_validate_errors() -> None:
    with pytest.raises(ValueError):
        normalize_weights({"ml": "not-a-number"})
    with pytest.raises(ValueError):
        normalize_weights({"ml": -1})