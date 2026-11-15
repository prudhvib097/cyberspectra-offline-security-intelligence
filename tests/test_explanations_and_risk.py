from __future__ import annotations

import pandas as pd

from backend.explanations import build_explanations
from backend.risk import build_risk_scores
from backend.config import DEFAULT_CONFIG


def test_risk_and_explanations_enrich_scored_frame() -> None:
    frame = pd.DataFrame(
        [
            {
                "message": "multiple failed login attempts",
                "source_file": "auth.log",
                "anomaly_score": 0.85,
                "failed_login_count": 4,
                "message_word_count": 6,
            }
        ]
    )

    scored = build_risk_scores(frame, config=DEFAULT_CONFIG)
    scored = build_explanations(scored)

    assert scored["risk_score"].iloc[0] > 0
    assert scored["explanation"].iloc[0].startswith("High-risk pattern")
    assert scored["alert_message"].iloc[0] == scored["explanation"].iloc[0]
