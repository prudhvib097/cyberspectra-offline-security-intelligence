"""Generic application-log parser (ISO timestamp + level markers).

Example:
    2026-05-01 10:00:07,123 [ERROR] [PaymentService] timeout calling upstream
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "app"

_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"[ \t-]*"
    r"(?P<level>\[?(?:CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\]?)?"
    r"(?P<body>.*)$"
)
_LEVEL_TOKEN = re.compile(r"\b(CRITICAL|ERROR|WARN|WARNING|INFO|DEBUG|TRACE)\b", re.IGNORECASE)


def detect(text: str) -> bool:
    match = _ISO.match(text.strip())
    if not match:
        return False
    return bool(_LEVEL_TOKEN.search(text) and (len(text) > 20))


def parse(text: str) -> dict[str, Any]:
    match = _ISO.match(text.strip())
    if not match:
        return {"timestamp": pd.NaT, "message": text.strip(), "event_type": "app", "level": "INFO"}
    timestamp = pd.to_datetime(match.group("timestamp").replace(",", "."), errors="coerce")
    level = (match.group("level") or "INFO").upper().replace("[", "").replace("]", "")
    if level in ("WARN",):
        level = "WARNING"
    return {
        "timestamp": timestamp,
        "level": level,
        "message": (match.group("body") or "").strip() or text.strip(),
        "event_type": "error" if level in ("ERROR", "CRITICAL") else "app",
    }