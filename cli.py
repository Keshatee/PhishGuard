#!/usr/bin/env python3
"""
PhishGuard CLI

Usage:
    python cli.py path/to/email.eml
    python cli.py path/to/folder/ --json
    python cli.py path/to/folder/ --csv results.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        """Keep offline analysis usable when optional dotenv support is absent."""
        return False

from phishguard.analyzers.attachments import analyze_attachments
from phishguard.analyzers.content import analyze_content
from phishguard.analyzers.links import analyze_links, check_url_reputation, extract_urls, follow_redirects
from phishguard.analyzers.sender import analyze_sender
from phishguard.parser import parse_eml
from phishguard.report import format_json, format_text
from phishguard.scoring import compute_risk_score
from phishguard import __version__

load_dotenv()


def analyze_file(path: Path):
    parsed = parse_eml(path)

    sender_findings = analyze_sender(parsed)
    urls = extract_urls(parsed)
    link_findings = analyze_links(urls)
    network_enabled = os.getenv("PHISHGUARD_ENABLE_NETWORK_LOOKUPS", "").lower() in {"1", "true", "yes"}
    if network_enabled:
        for url in urls:
            reputation = check_url_reputation(url)
            if reputation and reputation.get("flagged"):
                link_findings.append(
                    {
                        "signal": "blocklist_match",
                        "weight": 60,
                        "detail": f"URL was flagged by {reputation['source']}: {url}",
                    }
                )
            destination = follow_redirects(url)
            if destination:
                link_findings.append(
                    {
                        "signal": "redirect_destination",
                        "weight": 15,
                        "detail": f"URL redirects to a different destination: {destination}",
                    }
                )
    attachment_findings = analyze_attachments(parsed["attachments"])
    content_findings = analyze_content(parsed)

    report = compute_risk_score(
        sender_findings, link_findings, attachment_findings, content_findings
    )
    return report, parsed, urls


def collect_eml_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(path for path in target.iterdir() if path.is_file() and path.suffix.lower() == ".eml")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard: phishing risk analyzer")
    parser.add_argument("--version", action="version", version=f"PhishGuard {__version__}")
    parser.add_argument("path", help="Path to a .eml file or a folder of .eml files")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    parser.add_argument("--csv", metavar="FILE", help="Write a CSV summary report to FILE (batch mode)")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        sys.exit(1)

    files = collect_eml_files(target)
    if not files:
        print(f"Error: no .eml files found at {target}", file=sys.stderr)
        sys.exit(1)

    csv_rows = []

    failed_files = 0
    for file_path in files:
        try:
            report, parsed, urls = analyze_file(file_path)
        except Exception as exc:
            failed_files += 1
            print(f"Failed to analyze {file_path.name}: {exc}", file=sys.stderr)
            continue

        if args.json:
            print(format_json(report, source_label=file_path.name))
        else:
            print(format_text(report, source_label=file_path.name))
            print()

        if args.csv:
            csv_rows.append(
                {
                    "file": file_path.name,
                    "from": parsed.get("from_address", ""),
                    "subject": parsed.get("subject", ""),
                    "overall_score": report.overall_score,
                    "verdict": report.verdict,
                    "sender_score": round(report.category_scores["sender"].raw_score),
                    "links_score": round(report.category_scores["links"].raw_score),
                    "attachments_score": round(report.category_scores["attachments"].raw_score),
                    "content_score": round(report.category_scores["content"].raw_score),
                    "url_count": len(urls),
                    "attachment_count": len(parsed.get("attachments", [])),
                }
            )

    if args.csv and csv_rows:
        with open(args.csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"CSV summary written to {args.csv}")

    if failed_files == len(files):
        sys.exit(1)


if __name__ == "__main__":
    main()
