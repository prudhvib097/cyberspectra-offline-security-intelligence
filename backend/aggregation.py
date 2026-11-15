from __future__ import annotations

import re
from typing import Any

import numpy as np
import pandas as pd

from backend.config import DEFAULT_CONFIG, load_config

LOGIN_HINTS = (r"\blogin|logon|auth|authentication|password|sshd",)
FAILED_HINTS = (r"\bfailed|denied|invalid|refused|unauthorized|failure\b",)
SUCCESS_HINTS = (r"\baccepted|success(?:ful)?|\bok\b|\bnew session\b",)

_IP_PATTERN = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})")
_USERNAME_PATTERNS = [
    re.compile(r"(?:user|username)\s*[=:]\s*(\S+)"),
    re.compile(r"for\s+(?:invalid\s+)?(?:user\s+)?(\S+)\s+from\b"),
    re.compile(r"Accepted (?:publickey|password) for (\S+)"),
    re.compile(r"(?:useradd|passwd|sudo)[:\s]+user[=: ](\S+)"),
    re.compile(r"\buser\s+(\S+)\b"),
]
_PORT_RE = re.compile(r"port\s+(\d+)", re.IGNORECASE)
COMMON_PORTS = {22, 53, 80, 443, 88, 135, 139, 445, 3389, 8080}


def extract_source_ip(frame: pd.DataFrame) -> pd.Series:
    """Best-effort IPv4 extraction from raw log text."""
    if frame.empty:
        return pd.Series([], dtype=str)
    text = (frame.get("raw_line", frame.get("message", "")).astype(str) + " " + frame.get("message", "").astype(str))
    return text.str.extract(_IP_PATTERN.pattern, expand=False).fillna("")


def extract_username(frame: pd.DataFrame) -> pd.Series:
    """Best-effort username extraction from raw log text."""
    if frame.empty:
        return pd.Series([], dtype=str)
    text = (frame.get("raw_line", frame.get("message", "")).astype(str) + " " + frame.get("message", "").astype(str))
    extracted = pd.Series("", index=frame.index, dtype=str)
    for pattern in _USERNAME_PATTERNS:
        found = text.str.extract(pattern.pattern, expand=False)
        mask = found.notna() & (found != "")
        extracted = extracted.where(~mask, found)
    return extracted


def _window_counts(times: np.ndarray, flagged: np.ndarray, window_ns: int) -> np.ndarray:
    """Vectorized count of flagged events per row within [t - window, t].

    `times` must be sorted ascending. `flagged` indicates which times belong
    to the counted subset. Rows with flag False return 0.
    """
    counts = np.zeros(len(times), dtype=int)
    flagged_idx = np.flatnonzero(flagged)
    if flagged_idx.size == 0:
        return counts
    flagged_times = times[flagged_idx]
    left = np.searchsorted(flagged_times, times - window_ns, side="left")
    right = np.searchsorted(flagged_times, times, side="right")
    return right - left


def _sorted_timestamps(frame: pd.DataFrame) -> np.ndarray:
    """Return monotonic datetime64[ns] values.

    NaT rows fall back to the most recent valid timestamp so aggregation stays
    stable when timestamps are missing; if none exist, positions are used.
    """
    arr = frame["timestamp"].to_numpy(dtype="datetime64[ns]")
    valid = ~np.isnat(arr)
    if not valid.any():
        return np.arange(len(arr)).astype("datetime64[ns]")
    int_values = arr.astype("int64")
    fallback = np.where(valid, int_values, -1)
    backfilled = pd.Series(fallback).where(pd.Series(fallback) >= 0).ffill().fillna(int_values[valid][0]).astype(np.int64).to_numpy()
    return backfilled.astype("datetime64[ns]")


def _window_uniques(times: np.ndarray, values: np.ndarray, window_ns: int) -> np.ndarray:
    """Count distinct ``values`` seen for each row within [t - window, t].

    ``times`` must be sorted ascending. Two-pointer sweep gives O(n) per group.
    """
    n = len(times)
    counts_by_value: dict[Any, int] = {}
    unique = 0
    left = 0
    out = np.zeros(n, dtype=int)
    for right in range(n):
        value = values[right]
        previous = counts_by_value.get(value, 0)
        if previous == 0:
            unique += 1
        counts_by_value[value] = previous + 1
        window_start = times[right] - window_ns
        while left < right and times[left] < window_start:
            leaving = values[left]
            remaining = counts_by_value[leaving] - 1
            if remaining == 0:
                del counts_by_value[leaving]
                unique -= 1
            else:
                counts_by_value[leaving] = remaining
            left += 1
        out[right] = unique
    return out


def build_aggregated_features(frame: pd.DataFrame, config: dict[str, Any] | None = None) -> pd.DataFrame:
    """Add time-windowed behavioral features for authentication traffic.

    Produces per-row aggregates measured over a trailing time window keyed by
    (source IP, username):
        failed_login_count     failed authentication events in window
        login_attempt_count    all authentication attempts in window
        successful_login_count accepted/authenticated events in window
        failed_login_ratio     failed / total attempts (0 when no attempts)
        login_burst_score      min(1, failed / burst_threshold)

    Plus per-source behavioral signals (advanced features, additive):
        window_event_count         events of the same source in window
        event_rate_per_min         window events / window minutes
        failed_login_rate_per_min  failed events / window minutes
        unique_source_ips_window   distinct source IPs in window (per source)
        unique_usernames_window    distinct usernames in window (per source)
        time_since_previous_event_sec  seconds since previous event of source
        unusual_port               1 when a non-common port is referenced
    """
    if frame.empty:
        return frame.copy()

    settings = config or load_config()
    aggregation = settings.get("aggregation", {})
    window_seconds = float(aggregation.get("window_seconds", 120))
    burst_threshold = float(aggregation.get("login_burst_threshold", 5))
    window_ns = int(window_seconds * 1_000_000_000)

    aggregated = frame.copy()
    if "timestamp" not in aggregated.columns:
        aggregated["timestamp"] = pd.NaT

    sources = (aggregated.get("source_file", pd.Series([""] * len(aggregated), index=aggregated.index)).astype(str))

    text = (aggregated.get("raw_line", aggregated.get("message", "")).astype(str) + " " + aggregated.get("message", "").astype(str)).str.lower()

    is_login = text.str.contains("|".join(LOGIN_HINTS), regex=True, na=False)
    is_failed = text.str.contains("|".join(FAILED_HINTS), regex=True, na=False)
    is_success = text.str.contains("|".join(SUCCESS_HINTS), regex=True, na=False)

    ip_values = extract_source_ip(aggregated)
    user_values = extract_username(aggregated)
    aggregated["source_ip"] = ip_values
    aggregated["username"] = user_values

    key = sources + "|" + ip_values + "|" + user_values
    times = _sorted_timestamps(aggregated)

    failed_count = np.zeros(len(aggregated), dtype=int)
    attempt_count = np.zeros(len(aggregated), dtype=int)
    success_count = np.zeros(len(aggregated), dtype=int)

    flagged_failed = is_failed.to_numpy()
    flagged_attempt = is_login.to_numpy()
    flagged_success = is_success.to_numpy()

    order = times.argsort(kind="stable")
    sorted_times = times[order]
    group_of_sorted = key.to_numpy(dtype=object)[order]

    group_starts: dict[Any, int] = {}
    group_ends: dict[Any, int] = {}
    for position, group_key in enumerate(group_of_sorted):
        if group_key not in group_starts:
            group_starts[group_key] = position
        group_ends[group_key] = position + 1

    sorted_failed = flagged_failed[order]
    sorted_attempt = flagged_attempt[order]
    sorted_success = flagged_success[order]

    for group_key, start in group_starts.items():
        end = group_ends[group_key]
        group_times = sorted_times[start:end]
        contribution_failed = _window_counts(group_times, sorted_failed[start:end], window_ns)
        contribution_attempt = _window_counts(group_times, sorted_attempt[start:end], window_ns)
        contribution_success = _window_counts(group_times, sorted_success[start:end], window_ns)
        failed_count[order[start:end]] = contribution_failed
        attempt_count[order[start:end]] = contribution_attempt
        success_count[order[start:end]] = contribution_success

    aggregated["failed_login_count"] = failed_count
    aggregated["login_attempt_count"] = attempt_count
    aggregated["successful_login_count"] = success_count

    attempts = attempt_count
    aggregated["failed_login_ratio"] = np.divide(
        failed_count,
        attempts,
        out=np.zeros(len(aggregated), dtype=float),
        where=attempts > 0,
    )
    aggregated["login_burst_score"] = np.minimum(1.0, failed_count / max(burst_threshold, 1e-9))

    # ---- per-source behavioral signals over the same trailing window ----
    source_group_key = sources.to_numpy()
    sorted_source_keys = source_group_key[order]
    source_starts: dict[Any, int] = {}
    source_ends: dict[Any, int] = {}
    for position, group_key in enumerate(sorted_source_keys):
        source_key = group_key
        if source_key not in source_starts:
            source_starts[source_key] = position
        source_ends[source_key] = position + 1

    window_event_count = np.zeros(len(aggregated), dtype=int)
    unique_ips = np.zeros(len(aggregated), dtype=int)
    unique_users = np.zeros(len(aggregated), dtype=int)
    for source_key, start in source_starts.items():
        end = source_ends[source_key]
        group_times = sorted_times[start:end]
        window_event_count[order[start:end]] = _window_counts(group_times, np.ones(end - start, dtype=bool), window_ns)
        ips_sorted = ip_values.to_numpy()[order[start:end]]
        users_sorted = user_values.to_numpy()[order[start:end]]
        unique_ips[order[start:end]] = _window_uniques(group_times, ips_sorted, window_ns)
        unique_users[order[start:end]] = _window_uniques(group_times, users_sorted, window_ns)

    aggregated["window_event_count"] = window_event_count
    window_minutes = max(window_seconds / 60.0, 1e-9)
    aggregated["event_rate_per_min"] = window_event_count / window_minutes
    aggregated["failed_login_rate_per_min"] = failed_count / window_minutes

    time_diffs = np.zeros(len(aggregated), dtype=float)
    for source_key, start in source_starts.items():
        end = source_ends[source_key]
        segment_times = sorted_times[start:end]
        if end - start > 1:
            diff_values = (segment_times[1:] - segment_times[:-1]) / 1_000_000_000.0
            time_diffs[order[start + 1 : end]] = diff_values
    aggregated["time_since_previous_event_sec"] = pd.Series(time_diffs, index=aggregated.index)

    port_match = (aggregated.get("raw_line", aggregated.get("message", "")).astype(str) + " " + aggregated.get("message", "").astype(str)).str.extract(
        r"port\s+(\d+)", expand=False
    )
    port_values = pd.to_numeric(port_match, errors="coerce")
    aggregated["unusual_port"] = (port_values.notna() & ~port_values.isin(COMMON_PORTS)).astype(int)

    aggregated["unique_source_ips_window"] = pd.Series(unique_ips, index=aggregated.index)
    aggregated["unique_usernames_window"] = pd.Series(unique_users, index=aggregated.index)

    return aggregated