from __future__ import annotations

import pandas as pd

from backend.aggregation import build_aggregated_features


def _bruteforce_frame() -> pd.DataFrame:
    rows = []
    for attempt in range(40):
        rows.append(
            {
                "timestamp": pd.Timestamp("2026-05-01 10:00:00") + pd.Timedelta(seconds=attempt * 3),
                "raw_line": f"2026-05-01 10:00:{attempt:02d} host sshd: Failed password for admin from 192.168.1.20 port 58421 ssh2",
                "message": f"Failed password for admin from 192.168.1.20 port 58421",
                "source_file": "auth.log",
                "source": "auth.log",
                "line_number": attempt + 1,
            }
        )
    rows.append(
        {
            "timestamp": pd.Timestamp("2026-05-01 10:00:00"),
            "raw_line": "2026-05-01 10:00:00 host sshd: Accepted publickey for analyst from 10.0.1.10 port 58430 ssh2",
            "message": "Accepted publickey for analyst from 10.0.1.10",
            "source_file": "auth.log",
            "source": "auth.log",
            "line_number": 100,
        }
    )
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def test_failed_login_counts_are_window_aggregated_not_flags() -> None:
    frame = build_aggregated_features(_bruteforce_frame())
    failed_rows = frame[frame["failed_login_count"] > 0]
    assert failed_rows["failed_login_count"].max() > 3
    assert frame["failed_login_count"].max() >= 40
    assert frame["login_attempt_count"].max() >= 40


def test_ratio_and_burst_score_derived() -> None:
    frame = build_aggregated_features(_bruteforce_frame())
    burst_rows = frame[frame["login_burst_score"] > 0]
    assert not burst_rows.empty
    assert (burst_rows["failed_login_ratio"] >= 0).all()
    assert (burst_rows["failed_login_ratio"] <= 1).all()
    # windowed ratio converges toward 1.0 as the burst dominates the window
    assert burst_rows["failed_login_ratio"].iloc[-1] > 0.9
    saturated = burst_rows[burst_rows["failed_login_count"] >= 5]
    assert (saturated["login_burst_score"] == 1.0).all()


def test_session_accepted_success_does_not_inflate_failures() -> None:
    frame = build_aggregated_features(_bruteforce_frame())
    accepted = frame[frame["message"].str.contains("Accepted")]
    assert accepted["failed_login_count"].iloc[0] == 0
    assert accepted["successful_login_count"].iloc[0] == 1


def test_ip_and_username_extracted() -> None:
    frame = build_aggregated_features(_bruteforce_frame())
    assert (frame["source_ip"] == "192.168.1.20").any()
    assert (frame["username"] == "admin").any()
    assert (frame["username"] == "analyst").any()


def test_distant_events_do_not_accumulate() -> None:
    rows = [
        {
            "timestamp": pd.Timestamp("2026-05-01 08:00:00"),
            "raw_line": "Failed password for root from 10.0.0.9 port 1 ssh2",
            "message": "Failed password for root",
            "source_file": "auth.log",
            "source": "auth.log",
            "line_number": 1,
        },
        {
            "timestamp": pd.Timestamp("2026-05-02 08:00:00"),
            "raw_line": "Failed password for root from 10.0.0.9 port 2 ssh2",
            "message": "Failed password for root",
            "source_file": "auth.log",
            "source": "auth.log",
            "line_number": 2,
        },
    ]
    frame = build_aggregated_features(pd.DataFrame(rows))
    assert frame["failed_login_count"].max() == 1  # 24h apart, outside the 120s window


def test_missing_timestamps_do_not_crash() -> None:
    frame = pd.DataFrame(
        [
            {"raw_line": "Failed password for user x from 10.0.0.1", "message": "Failed password", "source_file": "a.log", "source": "a.log", "timestamp": pd.NaT, "line_number": i + 1}
            for i in range(5)
        ]
    )
    aggregated = build_aggregated_features(frame)
    # NaT rows fall back to nearest-known time, so counts accumulate within the group
    assert aggregated["failed_login_count"].tolist() == [1, 2, 3, 4, 5]
    assert aggregated["failed_login_ratio"].tolist() == [1.0, 1.0, 1.0, 1.0, 1.0]