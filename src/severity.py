from __future__ import annotations

import numpy as np
import pandas as pd

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {
    "Low": "#43a047",
    "Medium": "#f9a825",
    "High": "#ef6c00",
    "Critical": "#c62828",
}


def _severity_from_score(score: float) -> str:
    if score > 0.8:
        return "Critical"
    if score >= 0.6:
        return "High"
    if score >= 0.3:
        return "Medium"
    return "Low"


def assign_severity(frame: pd.DataFrame) -> pd.DataFrame:
    """Map normalized anomaly scores to operational severity labels."""
    if frame.empty:
        return frame.copy()

    scored = frame.copy()
    if "anomaly_score" not in scored.columns:
        scored["anomaly_score"] = 0.0

    scored["anomaly_score"] = pd.to_numeric(scored["anomaly_score"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    scores = scored["anomaly_score"]
    scored["severity"] = np.select([scores > 0.8, scores >= 0.6, scores >= 0.3], ["Critical", "High", "Medium"], default="Low")
    if "prediction" in scored.columns:
        scored.loc[scored["prediction"] != -1, "severity"] = "Low"
    scored["alert_required"] = scored["severity"].isin(["Medium", "High", "Critical"])
    scored["severity_rank"] = scored["severity"].map({name: index + 1 for index, name in enumerate(SEVERITY_ORDER)}).fillna(1).astype(int)
    scored["severity_color"] = scored["severity"].map(SEVERITY_COLORS).fillna(SEVERITY_COLORS["Low"])
    source_files = scored["source_file"].astype(str) if "source_file" in scored.columns else pd.Series("log stream", index=scored.index)
    scored["alert_message"] = np.where(
        scored["alert_required"],
        scored["severity"].astype(str) + " severity alert: anomaly detected in " + source_files,
        "Normal event",
    )
    return scored


def summarize_severity(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame(columns=["severity", "count"])
    summary = frame.groupby("severity", dropna=False).size().reset_index(name="count")
    summary["severity"] = pd.Categorical(summary["severity"], categories=SEVERITY_ORDER, ordered=True)
    summary = summary.sort_values("severity")
    return summary
