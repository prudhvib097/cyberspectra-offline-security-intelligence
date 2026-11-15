"""AWS CloudTrail line parser (single JSON object on one line)."""

from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd

PARSER_ID = "cloudtrail"

_EVENT_NAME_RE = re.compile(r'"eventName"\s*:\s*"([^"]+)"', re.IGNORECASE)
_SECURITY_EVENTS = {
    "consolelogin",
    "createloginprofile",
    "createaccesskey",
    "updateaccesskey",
    "deleteloginprofile",
    "putuserpolicy",
    "attachuserpolicy",
    "authorizesecuritygroupingress",
}


def detect(text: str) -> bool:
    if not text.lstrip().startswith("{"):
        return False
    return bool(_EVENT_NAME_RE.search(text))


def parse(text: str) -> dict[str, Any]:
    record: dict[str, Any] = {"message": text.strip(), "event_type": "cloud", "level": "INFO"}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        record["parse_status"] = "unparsed"
        payload = {}

    record["source_ip"] = str(payload.get("sourceIPAddress") or "")
    event_name = str(payload.get("eventName") or "")
    record["event_type"] = event_name if event_name else "cloud"
    record["message"] = f"{event_name} {str(payload.get('eventSource') or '')} eventType={str(payload.get('eventType') or '')}"

    timestamp_value = payload.get("eventTime")
    timestamp = pd.to_datetime(timestamp_value, errors="coerce") if timestamp_value else pd.NaT
    record["timestamp"] = timestamp
    record["username"] = str(payload.get("userIdentity", {}).get("userName") or payload.get("userIdentity", {}).get("accessKeyId") or "")
    record["level"] = "WARNING" if event_name.lower() in _SECURITY_EVENTS else "INFO"
    record["event_name"] = event_name
    record["request_id"] = str(payload.get("requestID") or "")
    record["service"] = str(payload.get("eventSource") or "")
    return record