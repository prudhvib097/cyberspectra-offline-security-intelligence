from __future__ import annotations

import re
from typing import List

import numpy as np
import pandas as pd

ALERT_KEYWORDS = [
    "failed",
    "failure",
    "error",
    "exception",
    "timeout",
    "unauthorized",
    "denied",
    "critical",
    "panic",
    "breach",
    "attack",
    "malware",
    "overflow",
    "corrupt",
    "invalid",
    "refused",
    "blocked",
]

SECURITY_KEYWORDS = ["auth", "login", "password", "token", "credential", "access", "session"]
NETWORK_KEYWORDS = ["network", "ip", "port", "connection", "socket", "packet", "dns", "firewall", "http", "https"]
SYSTEM_KEYWORDS = ["kernel", "disk", "memory", "cpu", "service", "process", "scheduler", "database"]
WEB_KEYWORDS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "apache", "nginx", "request", "response"]
AWS_KEYWORDS = ["cloudtrail", "aws", "ec2", "iam", "s3", "lambda", "vpc", "guardduty", "console"]

FEATURE_COLUMNS = [
    "message_length",
    "message_word_count",
    "unique_word_count",
    "digit_count",
    "alpha_count",
    "uppercase_count",
    "uppercase_ratio",
    "punctuation_count",
    "special_symbol_count",
    "alert_keyword_count",
    "security_keyword_count",
    "network_keyword_count",
    "system_keyword_count",
    "web_keyword_count",
    "aws_keyword_count",
    "exclamation_count",
    "question_count",
    "has_ip_address",
    "ip_frequency",
    "has_error_code",
    "has_http_status",
    "login_attempt_count",
    "failed_login_count",
    "successful_login_count",
    "failed_login_ratio",
    "login_burst_score",
    "window_event_count",
    "event_rate_per_min",
    "failed_login_rate_per_min",
    "unique_source_ips_window",
    "unique_usernames_window",
    "time_since_previous_event_sec",
    "unusual_port",
    "request_verb_count",
    "path_token_count",
    "keyword_density",
    "digit_to_alpha_ratio",
    "timestamp_known",
    "event_hour",
    "event_dayofweek",
    "is_business_hours",
    "is_weekend",
    "source_event_count",
    "source_line_density",
    "hour_event_count",
    "source_name_length",
    "source_kind_linux",
    "source_kind_windows",
    "source_kind_web",
    "source_kind_cloud",
]


def _count_matches(text: pd.Series, keywords: List[str]) -> pd.Series:
    pattern = r"\b(?:" + "|".join(re.escape(keyword) for keyword in keywords) + r")\b"
    return text.str.count(pattern, flags=re.IGNORECASE)


def _detect_source_kind(frame: pd.DataFrame) -> pd.Series:
    source_text = (
        frame.get("source_file", pd.Series([""] * len(frame), index=frame.index)).astype(str)
        + " "
        + frame.get("source_path", pd.Series([""] * len(frame), index=frame.index)).astype(str)
    ).str.lower()
    linux_mask = source_text.str.contains(r"syslog|auth\.log|secure|messages")
    windows_mask = source_text.str.contains(r"windows|event|evtx|security|system|application")
    web_mask = source_text.str.contains(r"apache|nginx|access|error|webserver|httpd")
    cloud_mask = source_text.str.contains(r"aws|cloudtrail|cloud|lambda|guardduty|s3|iam")
    return pd.DataFrame(
        {
            "source_kind_linux": linux_mask.astype(int),
            "source_kind_windows": windows_mask.astype(int),
            "source_kind_web": web_mask.astype(int),
            "source_kind_cloud": cloud_mask.astype(int),
        },
        index=frame.index,
    )


def build_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Turn cleaned log messages into numeric signals for anomaly detection."""
    if frame.empty:
        return frame.copy()

    engineered = frame.copy()
    message_series = engineered.get("normalized_message", engineered.get("message", "")).fillna("").astype(str)
    tokens = message_series.str.split()

    engineered["message_length"] = message_series.str.len()
    engineered["message_word_count"] = tokens.map(len).fillna(0).astype(int)
    engineered["unique_word_count"] = tokens.apply(lambda values: len(set(values)) if isinstance(values, list) else 0)
    engineered["digit_count"] = message_series.str.count(r"\d")
    engineered["alpha_count"] = message_series.str.count(r"[A-Za-z]")
    engineered["uppercase_count"] = engineered.get("message", message_series).astype(str).str.count(r"[A-Z]")
    engineered["uppercase_ratio"] = np.where(
        engineered["message_length"] > 0,
        engineered["uppercase_count"] / engineered["message_length"],
        0.0,
    )
    engineered["punctuation_count"] = message_series.str.count(r"[\.,;:|\-_()\[\]{}<>/]")
    engineered["special_symbol_count"] = message_series.str.count(r"[^\w\s]")
    engineered["alert_keyword_count"] = _count_matches(message_series, ALERT_KEYWORDS)
    engineered["security_keyword_count"] = _count_matches(message_series, SECURITY_KEYWORDS)
    engineered["network_keyword_count"] = _count_matches(message_series, NETWORK_KEYWORDS)
    engineered["system_keyword_count"] = _count_matches(message_series, SYSTEM_KEYWORDS)
    engineered["web_keyword_count"] = _count_matches(message_series, WEB_KEYWORDS)
    engineered["aws_keyword_count"] = _count_matches(message_series, AWS_KEYWORDS)
    engineered["exclamation_count"] = message_series.str.count(r"!")
    engineered["question_count"] = message_series.str.count(r"\?")

    ip_matches = message_series.str.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    engineered["has_ip_address"] = ip_matches.map(lambda values: int(bool(values)))
    engineered["ip_frequency"] = ip_matches.map(len)
    engineered["has_error_code"] = message_series.str.contains(
        r"\b(?:err|error|code|exception|0x[0-9a-f]+|[A-Z]{2,}-?\d{2,})\b",
        regex=True,
        case=False,
        na=False,
    ).astype(int)
    engineered["has_http_status"] = message_series.str.contains(r"\b(?:1\d{2}|2\d{2}|3\d{2}|4\d{2}|5\d{2})\b", regex=True, na=False).astype(int)
    login_mask = message_series.str.contains(r"\blogin|logon|auth|authentication|password\b", regex=True, case=False, na=False)
    failed_mask = message_series.str.contains(r"\bfailed|denied|invalid|refused|unauthorized\b", regex=True, case=False, na=False)
    success_mask = message_series.str.contains(r"\baccepted|success(?:ful)?|\bok\b|\bnew session\b", regex=True, case=False, na=False)
    if "login_attempt_count" not in engineered.columns:
        engineered["login_attempt_count"] = login_mask.astype(int)
    else:
        engineered["login_attempt_count"] = pd.to_numeric(engineered["login_attempt_count"], errors="coerce").fillna(0).astype(int)
    if "failed_login_count" not in engineered.columns:
        engineered["failed_login_count"] = (login_mask & failed_mask).astype(int)
    else:
        engineered["failed_login_count"] = pd.to_numeric(engineered["failed_login_count"], errors="coerce").fillna(0).astype(int)
    if "successful_login_count" not in engineered.columns:
        engineered["successful_login_count"] = success_mask.astype(int)
    else:
        engineered["successful_login_count"] = pd.to_numeric(engineered["successful_login_count"], errors="coerce").fillna(0).astype(int)
    if "failed_login_ratio" not in engineered.columns:
        attempts = engineered["login_attempt_count"] + engineered["successful_login_count"]
        engineered["failed_login_ratio"] = np.where(attempts > 0, engineered["failed_login_count"] / attempts, 0.0)
    else:
        engineered["failed_login_ratio"] = pd.to_numeric(engineered["failed_login_ratio"], errors="coerce").fillna(0.0)
    if "login_burst_score" not in engineered.columns:
        engineered["login_burst_score"] = np.minimum(1.0, engineered["failed_login_count"] / 5.0)
    else:
        engineered["login_burst_score"] = pd.to_numeric(engineered["login_burst_score"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
    engineered["request_verb_count"] = message_series.str.count(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD)\b")
    engineered["path_token_count"] = message_series.str.count(r"/[A-Za-z0-9_\-.]+")

    total_keyword_hits = (
        engineered["alert_keyword_count"]
        + engineered["security_keyword_count"]
        + engineered["network_keyword_count"]
        + engineered["system_keyword_count"]
        + engineered["web_keyword_count"]
        + engineered["aws_keyword_count"]
    )
    engineered["keyword_density"] = np.where(
        engineered["message_word_count"] > 0,
        total_keyword_hits / engineered["message_word_count"],
        0.0,
    )
    engineered["digit_to_alpha_ratio"] = np.where(
        engineered["alpha_count"] > 0,
        engineered["digit_count"] / engineered["alpha_count"],
        0.0,
    )

    engineered["timestamp_known"] = engineered["timestamp"].notna().astype(int)
    engineered["event_hour"] = engineered.get("event_hour", pd.Series([-1] * len(engineered), index=engineered.index)).fillna(-1).astype(int)
    engineered["event_dayofweek"] = engineered.get("event_dayofweek", pd.Series([-1] * len(engineered), index=engineered.index)).fillna(-1).astype(int)
    engineered["is_business_hours"] = engineered.get("is_business_hours", pd.Series([0] * len(engineered), index=engineered.index)).fillna(0).astype(int)
    engineered["is_weekend"] = engineered.get("is_weekend", pd.Series([0] * len(engineered), index=engineered.index)).fillna(0).astype(int)
    engineered["source_name_length"] = engineered.get("source_file", pd.Series([""] * len(engineered), index=engineered.index)).astype(str).str.len()

    source_event_count = engineered.groupby("source_file", dropna=False)["source_file"].transform("size")
    engineered["source_event_count"] = source_event_count.astype(int)
    if len(engineered) > 0:
        engineered["source_line_density"] = engineered["source_event_count"] / float(engineered["source_event_count"].max())
    else:
        engineered["source_line_density"] = 0.0
    engineered["hour_event_count"] = engineered.groupby("event_hour", dropna=False)["event_hour"].transform("size").astype(int)

    source_kind_frame = _detect_source_kind(engineered)
    for column in source_kind_frame.columns:
        engineered[column] = source_kind_frame[column].astype(int)

    for column in FEATURE_COLUMNS:
        engineered[column] = pd.to_numeric(engineered.get(column, 0), errors="coerce").fillna(0)

    return engineered


def get_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    feature_frame = frame.copy()
    for column in FEATURE_COLUMNS:
        if column not in feature_frame.columns:
            feature_frame[column] = 0
    return feature_frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0)
