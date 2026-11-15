"""Network flow / Suricata / DNS log parser.

Examples:
    05/01/2026-10:00:07.123456  [**] [1:2000000:1] ET SCAN Potential SSH Scan 203.0.113.9 -> 10.0.0.5
    2026-05-01 10:00:07 dnsmasq[1234]: query[A] evil.example.com from 10.0.0.9
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "network"

_SURICATA = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<sid>[\d:]+)\]\s+(?P<message>.*?)\s+(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(?P<dst>\d{1,3}(?:\.\d{1,3}){3})$"
)
_SYSLOG_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^:\s\[\]]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_THREAT_HINTS = ["scan", "attack", "malware", "exploit", "c2", "botnet", "brute", "sweep"]


def detect(text: str) -> bool:
    lowered = text.lower()
    return bool(_SURICATA.match(text)) or any(
        token in lowered
        for token in ["suricata", "snort", "dnsmasq", "netflow", "scan", "-> "]
    ) and " packet" not in lowered


def parse(text: str) -> dict[str, Any]:
    match = _SURICATA.match(text.strip())
    if match:
        timestamp = pd.to_datetime(match.group("timestamp").replace("/", "-", 1), errors="coerce")
        if pd.isna(timestamp):
            timestamp = pd.to_datetime(match.group("timestamp").split("-")[1], errors="coerce")
        lowered = match.group("message").lower()
        return {
            "timestamp": timestamp,
            "source_ip": match.group("src"),
            "destination_ip": match.group("dst"),
            "message": match.group("message"),
            "event_type": "network" if not any(hint in lowered for hint in _THREAT_HINTS) else "auth_failure",
            "level": "WARNING" if any(hint in lowered for hint in _THREAT_HINTS) else "INFO",
        }

    match = _SYSLOG_ISO.match(text.strip())
    if match:
        ips = _IP_RE.findall(text.strip())
        lowered = match.group("message").lower()
        return {
            "timestamp": pd.to_datetime(match.group("timestamp"), errors="coerce"),
            "source_host": match.group("host"),
            "source_ip": ips[0] if ips else "",
            "message": match.group("message"),
            "event_type": "network",
            "level": _infer_level(lowered),
        }

    ips = _IP_RE.findall(text.strip())
    return {
        "timestamp": pd.NaT,
        "source_ip": ips[0] if ips else "",
        "message": text.strip(),
        "event_type": "network",
        "level": _infer_level(text.lower()),
    }


def _infer_level(lowered: str) -> str:
    if "error" in lowered:
        return "ERROR"
    if "warn" in lowered or "unusual" in lowered:
        return "WARNING"
    return "INFO"