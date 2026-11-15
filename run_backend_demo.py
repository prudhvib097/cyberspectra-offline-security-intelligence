from __future__ import annotations

import argparse
from pathlib import Path
import sys

import pandas as pd

from backend.pipeline import run_pipeline_on_paths
from backend.reporting import export_csv_bytes, export_pdf_bytes


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backend demo runner")
    parser.add_argument("paths", nargs="+", help="Input log files or directories")
    parser.add_argument("--output-dir", default="reports/demo_run", help="Directory for exported reports")
    parser.add_argument("--contamination", type=float, default=0.12, help="Model contamination/sensitivity")
    parser.add_argument("--algorithm", choices=["isolation_forest", "one_class_svm"], default="isolation_forest")
    parser.add_argument("--sample", type=int, default=5, help="Number of sample alert rows to print")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    bundle = run_pipeline_on_paths(args.paths, contamination=args.contamination, algorithm=args.algorithm)

    # Print quick summary
    summary = bundle.summary if hasattr(bundle, "summary") else {}
    print("\n=== Backend Demo Summary ===")
    print(f"Processed rows: {summary.get('total_records', len(bundle.scored_frame) if not bundle.scored_frame.empty else 0)}")
    print(f"Anomalies detected: {summary.get('anomalies', int((bundle.scored_frame.get('prediction', pd.Series(dtype=int)) == -1).sum()) if not bundle.scored_frame.empty else 0)}")
    print(f"Severity counts: {summary.get('severity_counts', {})}\n")

    # Print a few alert rows if present
    alerts = getattr(bundle, "alert_feed", pd.DataFrame())
    if alerts is None or alerts.empty:
        print("No alerts to show.")
    else:
        print(f"Top {args.sample} alerts:")
        print(alerts.head(args.sample).to_string(index=False))

    # Write reports
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "processed_log_analysis.csv"
    pdf_path = out_dir / "offline_log_monitoring_report.pdf"
    csv_path.write_bytes(export_csv_bytes(bundle.scored_frame))
    pdf_path.write_bytes(export_pdf_bytes(bundle.scored_frame, title="CyberSpectra Report"))

    print(f"\nWrote CSV: {csv_path}")
    print(f"Wrote PDF: {pdf_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
