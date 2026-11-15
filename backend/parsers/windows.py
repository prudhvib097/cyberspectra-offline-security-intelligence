"""Windows Event Log line parser (ISO timestamps, event ids, providers).

Works on text extracted from CSV exports / wevtutil XML text nodes; the CSV
columns themselves are normalized by the schema and ingestion layer.
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "windows"

_ISO = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_EVENT_ID_RE = re.compile(r"\b(?:EventID|EventId|Event ID)[\s:=]*(\d+)", re.IGNORECASE)
_WER_ID_RE = re.compile(r'"(\d{3,5})","', re.IGNORECASE)
_SECURITY_IDS = {4624, 4625, 4634, 4648, 4672, 4624, 4720, 4732, 1102}


def detect(text: str) -> bool:
    return bool(_ISO.match(text)) and any(
        token in text.lower()
        for token in [
            "windows error reporting",
            "eventrecorder",
            "application,",
            "system,",
            "security,",
            "event id",
            "eventid",
            "audit",
            "microsoft-windows",
        ]
    )


def parse(text: str) -> dict[str, Any]:
    source_text = text.strip()
    timestamp = None
    timestamp_match = _ISO.search(source_text)
    if timestamp_match:
        timestamp = pd.to_datetime(timestamp_match.group("timestamp"), errors="coerce")

    event_match = _EVENT_ID_RE.search(source_text) or _WER_ID_RE.search(source_text)
    event_id = int(event_match.group(1)) if event_match else None

    lowered = source_text.lower()
    event_type = "system"
    if event_id in _SECURITY_IDS:
        event_type = "auth_failure" if event_id == 4625 else "auth"
    elif "error" in lowered or "fault" in lowered or "crash" in lowered:
        event_type = "error"

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": event_type,
        "level": "ERROR" if "error" in lowered or "fault" in lowered else "INFO",
        "message": source_text,
        "source": "windows-events",
    }