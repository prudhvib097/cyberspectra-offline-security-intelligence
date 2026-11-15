"""Firewall / ufw / iptables log parser.

Example:
    May 01 10:00:07 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.9 DST=10.0.0.5 LEN=40 TOS=0x00 PROTO=TCP SPT=54321 DPT=22
"""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

PARSER_ID = "firewall"

_PATTERN = re.compile(
    r"(?:^|\s)(?:\[UFW\s+(?P<action>BLOCK|ALLOW)\])|(?P<sfw>DROP|REJECT|ACCEPT)"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SRC_RE = re.compile(r"SRC=(\S+)", re.IGNORECASE)
_DST_RE = re.compile(r"DST=(\S+)", re.IGNORECASE)
_PROTO_RE = re.compile(r"PROTO=(\S+)", re.IGNORECASE)
_SPT_RE = re.compile(r"SPT=(\d+)", re.IGNORECASE)
_DPT_RE = re.compile(r"DPT=(\d+)", re.IGNORECASE)
_ISO_TS = re.compile(r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
_SYSLOG_TS = re.compile(r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})")


def detect(text: str) -> bool:
    lowered = text.lower()
    return "ufw" in lowered or "iptables" in lowered or "firewall" in lowered and ("src=" in lowered or "spt=" in lowered)


def parse(text: str) -> dict[str, Any]:
    match = _PATTERN.search(text)
    dropped = bool(match and (match.group("action") == "BLOCK" or match.group("sfw") in ("DROP", "REJECT")))
    timestamp_match = _ISO_TS.search(text) or _SYSLOG_TS.search(text)
    timestamp = pd.to_datetime(timestamp_match.group("timestamp"), errors="coerce") if timestamp_match else pd.NaT
    src = _SRC_RE.search(text)
    dst = _DST_RE.search(text)
    proto = _PROTO_RE.search(text)
    spt = _SPT_RE.search(text)
    dpt = _DPT_RE.search(text)
    return {
        "timestamp": timestamp,
        "source_ip": src.group(1) if src else "",
        "username": "",
        "event_type": "firewall",
        "level": "ERROR" if dropped else "INFO",
        "message": text.strip(),
        "firewall_action": match.group("action") if match and match.group("action") else (match.group("sfw") if match else ""),
        "protocol": proto.group(1) if proto else "",
        "source_port": int(spt.group(1)) if spt else None,
        "destination_ip": dst.group(1) if dst else "",
        "destination_port": int(dpt.group(1)) if dpt else None,
    }