"""JSON / JSONL parser.

Each line must be a valid JSON object. Keys are mapped through the common
schema aliases so downstream code sees canonical columns.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd

PARSER_ID = "jsonl"

_KEY_HINTS = [
    "eventName",
    "message",
    "msg",
    "log",
    "timestamp",
    "time",
    "level",
    "severity",
    "source",
    "event",
]


def detect(text: str) -> bool:
    stripped = text.lstrip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    stripped = stripped.lstrip("[")
    try:
        json.loads(stripped[:200])
        return True
    except Exception:
        return False


def _coerce_ts(value: Any) -> Any:
    if isinstance(value, (int, float)):
        return pd.to_datetime(value, unit="ms", errors="coerce")
    return value


def parse(text: str) -> dict[str, Any]:
    record: dict[str, Any] = {"message": text.strip(), "event_type": "json", "level": "INFO"}
    try:
        payload = json.loads(text.lstrip().lstrip("[").rstrip().rstrip("]"))
    except json.JSONDecodeError:
        record["parse_status"] = "unparsed"
        return record
    if not isinstance(payload, dict):
        record["parse_status"] = "unparsed"
        return record

    record.update(payload)
    record["raw_log"] = text.strip()
    if "timestamp" in record:
        record["timestamp"] = _coerce_ts(record["timestamp"])
    elif "time" in record:
        record["timestamp"] = _coerce_ts(record["time"])
    else:
        record["timestamp"] = pd.NaT
    level_value = record.get("level") or record.get("severity") or "INFO"
    record["level"] = str(level_value).upper().replace("WARN", "WARNING")
    message_value = record.get("message") or record.get("msg") or record.get("log") or text.strip()
    record["message"] = str(message_value)
    record["event_type"] = strategy_type_override(record)
    return record


def strategy_type_override(record: dict[str, Any]) -> str:
    event_name = str(record.get("eventName") or "").lower()
    if event_name:
        return event_name
    message = record.get("message", "")
    lowered = str(message).lower()
    if "failed" in lowered or "denied" in lowered or "invalid" in lowered:
        return "auth_failure"
    if "accepted" in lowered or "success" in lowered:
        return "auth_success"
    return str(record.get("event_type") or "json")