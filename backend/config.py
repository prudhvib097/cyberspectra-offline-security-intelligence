from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "defaults.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "model": {
        "default_contamination": 0.12,
        "weights": {
            "ml": 0.5,
            "statistical": 0.2,
            "rules": 0.2,
            "context": 0.1,
        },
    },
    "aggregation": {
        "window_seconds": 120,
        "login_burst_threshold": 5,
    },
    "monitoring": {
        "polling_interval_seconds": 10,
        "max_upload_size_mb": 200,
        "duplicate_prevention": True,
    },
    "risk": {
        "severity_boundaries": {"low": 25, "medium": 50, "high": 75, "critical": 100},
    },
    "rules": [
        {
            "rule_id": "repeated_failed_logins",
            "name": "Repeated failed logins",
            "description": "Detect bursty authentication failures",
            "enabled": True,
            "condition": "failed_login_count >= 3",
            "threshold": 3,
            "severity": "High",
            "weight": 1.2,
        }
    ],
}


def load_config(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    config_path = Path(path or CONFIG_PATH)
    if not config_path.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except Exception:
        return DEFAULT_CONFIG.copy()

    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update(loaded)
    if "model" in loaded and isinstance(loaded["model"], dict):
        merged["model"].update(loaded["model"])
    if "risk" in loaded and isinstance(loaded["risk"], dict):
        merged["risk"].update(loaded["risk"])
    if "rules" in loaded and isinstance(loaded["rules"], list):
        merged["rules"] = loaded["rules"]
    return merged


def save_config(config: dict[str, Any], path: str | os.PathLike[str] | None = None) -> Path:
    config_path = Path(path or CONFIG_PATH)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    return config_path
