from __future__ import annotations

import argparse
from pathlib import Path

from generate_monthly_report import generate_monthly_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate monthly vulnerability reports using CISA KEV, FIRST EPSS, and optional NVD data."
    )
    parser.add_argument(
        "--recent-days",
        type=int,
        default=30,
        help="Include vulnerabilities added or published within this many days. Default: 30.",
    )
    parser.add_argument(
        "--with-nvd",
        action="store_true",
        help="Fetch supplemental NVD data for selected CVEs when available.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Maximum number of vulnerabilities to include. Default: 20.",
    )
    parser.add_argument(
        "--mode",
        choices=("customer", "internal"),
        default="customer",
        help="Report audience. Default: customer.",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory. Default: output.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = generate_monthly_report(
        recent_days=args.recent_days,
        with_nvd=args.with_nvd,
        top=args.top,
        mode=args.mode,
        output_dir=Path(args.output),
    )
    print(f"Report written: {result.report_path}")
    print(f"CSV written: {result.csv_path}")
    if result.used_sample:
        print("Note: External data fetch failed or returned no rows; sample CSV was used.")


if __name__ == "__main__":
    main()
