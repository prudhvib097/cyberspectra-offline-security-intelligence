"""Generic syslog / central Log format parser (RFC-style and ISO timestamps).

Examples:
    May 01 10:00:07 myhost kernel: [ 1234.567] memory pressure
    2026-05-01 10:00:07 host service[123]: ready in 100ms
    <134>2026-05-01T10:00:07Z host app[1]: message
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "syslog"

_SYSLOG_RFC = re.compile(
    r"^(?:<\d+>\s*)?(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}(?:\s+\d{4})?)"
    r"\s+(?P<host>\S+)\s+(?P<program>[^:\s\[\]]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)
_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"(?:\s+(?P<host>\S+))?\s*(?P<message>.*)$"
)
_LEVEL_HINTS = [
    ("critical", "CRITICAL"),
    ("alert", "CRITICAL"),
    ("panic", "CRITICAL"),
    ("error", "ERROR"),
    ("err", "ERROR"),
    ("exception", "ERROR"),
    ("warning", "WARNING"),
    ("warn", "WARNING"),
    ("info", "INFO"),
    ("debug", "DEBUG"),
    ("trace", "TRACE"),
]


def detect(text: str) -> bool:
    if not text:
        return False
    return bool(_SYSLOG_RFC.match(text) or _ISO.match(text))


def _infer_level(message: str, program: str) -> str:
    lowered = f"{program} {message}".lower()
    for hint, level in _LEVEL_HINTS:
        if hint in lowered:
            return level
    return "INFO"


def parse(text: str) -> dict[str, Any]:
    match = _SYSLOG_RFC.match(text.strip())
    timestamp = None
    host = ""
    program = ""
    if match:
        timestamp = pd.to_datetime(match.group("timestamp"), errors="coerce")
        host = match.group("host")
        program = match.group("program")
        message = match.group("message")
    else:
        match = _ISO.match(text.strip())
        message = text.strip()
        if match:
            timestamp = pd.to_datetime(match.group("timestamp"), errors="coerce")
            host = match.group("host") or ""
            message = match.group("message").strip() or text.strip()

    return {
        "timestamp": timestamp,
        "source_host": host,
        "message": message,
        "source": program or "",
        "level": _infer_level(message, program),
        "event_type": "system",
    }