from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from backend.pipeline import run_pipeline_on_paths
from backend.reporting import export_csv_bytes, export_pdf_bytes


def launch_dashboard() -> int:
    command = [sys.executable, "-m", "streamlit", "run", "app/dashboard.py"]
    completed = subprocess.run(command, check=False)
    return completed.returncode


def run_batch_scan(input_paths: list[str], output_dir: str, contamination: float, algorithm: str) -> int:
    bundle = run_pipeline_on_paths(input_paths, contamination=contamination, algorithm=algorithm)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_path = output_path / "processed_log_analysis.csv"
    pdf_path = output_path / "offline_log_monitoring_report.pdf"
    csv_path.write_bytes(export_csv_bytes(bundle.scored_frame))
    pdf_path.write_bytes(export_pdf_bytes(bundle.scored_frame, title="CyberSpectra Report"))
    print(f"Processed {len(bundle.scored_frame)} rows")
    print(f"CSV report: {csv_path}")
    print(f"PDF report: {pdf_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline log monitoring system")
    parser.add_argument("paths", nargs="*", help="Input log files or directories")
    parser.add_argument("--dashboard", action="store_true", help="Launch the Streamlit dashboard")
    parser.add_argument("--output-dir", default="reports", help="Directory for exported reports")
    parser.add_argument("--contamination", type=float, default=0.12, help="Isolation Forest / One-Class SVM sensitivity")
    parser.add_argument("--algorithm", choices=["isolation_forest", "one_class_svm"], default="isolation_forest", help="Anomaly detection algorithm")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.dashboard or not args.paths:
        return launch_dashboard()

    return run_batch_scan(args.paths, args.output_dir, args.contamination, args.algorithm)


if __name__ == "__main__":
    raise SystemExit(main())