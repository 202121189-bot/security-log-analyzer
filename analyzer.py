#!/usr/bin/env python3
"""
Security Log Analyzer
======================
Analyzes Linux auth.log (and similar) to detect:
  - Brute-force attacks
  - Suspicious IPs
  - Failed vs successful logins
  - Invalid user attempts
  - Privilege escalation (sudo)

Outputs:
  - HTML report
  - JSON results
  - CSV files

Author: batool jameel
License: MIT
"""

import os
import sys
import csv
import json
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from parsers.linux_auth import parse_file
from detectors import brute_force, suspicious_ip


# --------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------

def banner(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def write_csv(path, rows, fieldnames=None):
    if not rows:
        return
    if fieldnames is None:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# --------------------------------------------------------------------
# Analysis Functions
# --------------------------------------------------------------------

def build_summary(events):
    """Build summary statistics from events."""
    event_counts = Counter(e["event_type"] for e in events)
    unique_ips = set(e["ip"] for e in events if e.get("ip"))
    unique_users = set(e["user"] for e in events if e.get("user"))

    return {
        "total_events": len(events),
        "event_counts": dict(event_counts),
        "unique_ips": len(unique_ips),
        "unique_users": len(unique_users),
    }


def build_timeline(events):
    """Build a timeline of events sorted by timestamp."""
    timeline = []
    for e in sorted(events, key=lambda x: x.get("timestamp", "")):
        timeline.append({
            "timestamp": e.get("timestamp", ""),
            "event_type": e["event_type"],
            "user": e.get("user", ""),
            "ip": e.get("ip", ""),
        })
    return timeline


def top_ips(events, limit=10):
    """Return top IPs by number of events."""
    counter = Counter(e["ip"] for e in events if e.get("ip"))
    return [{"ip": ip, "count": c} for ip, c in counter.most_common(limit)]


def top_users(events, limit=10):
    """Return top targeted users."""
    counter = Counter(e["user"] for e in events if e.get("user"))
    return [{"user": u, "count": c} for u, c in counter.most_common(limit)]


# --------------------------------------------------------------------
# Report Generation
# --------------------------------------------------------------------

def generate_report(data, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    write_json(output_dir / "analysis.json", data)

    # CSV: Events
    write_csv(output_dir / "events.csv", data["timeline"])

    # CSV: Brute force findings
    if data["brute_force"]:
        bf_rows = []
        for b in data["brute_force"]:
            bf_rows.append({
                "ip": b["ip"],
                "severity": b["severity"],
                "total_attempts": b["total_attempts"],
                "peak_in_window": b["peak_attempts_in_window"],
                "target_users": ", ".join(u for u, _ in b["target_usernames"]),
                "first_seen": b["first_seen"],
                "last_seen": b["last_seen"],
            })
        write_csv(output_dir / "brute_force.csv", bf_rows)

    # CSV: Suspicious IPs
    if data["suspicious_ips"]:
        write_csv(output_dir / "suspicious_ips.csv", data["suspicious_ips"])

    # HTML
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")

    html = template.render(
        data=data,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        source_file=data["metadata"]["source_file"],
    )

    with open(output_dir / "report.html", "w", encoding="utf-8") as f:
        f.write(html)

    return output_dir


# --------------------------------------------------------------------
# Entry Point
# --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - detect attacks in auth logs"
    )
    parser.add_argument("logfile", help="Path to log file (e.g., auth.log)")
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output directory (default: output/analysis_YYYYMMDD_HHMMSS)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.logfile):
        print(f"[!] File not found: {args.logfile}")
        sys.exit(1)

    if args.output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"output/analysis_{ts}"
    else:
        output_dir = args.output

    print("\n" + "=" * 60)
    print("  SECURITY LOG ANALYZER")
    print("=" * 60)
    print(f"  Source:  {args.logfile}")
    print(f"  Output:  {output_dir}")
    print(f"  Started: {datetime.now().isoformat(timespec='seconds')}")

    # ---------------------------------------------------------------
    # Step 1: Parse
    # ---------------------------------------------------------------
    banner("[1/4] Parsing log file")
    events = parse_file(args.logfile)
    print(f"  [+] Parsed {len(events)} events")

    if not events:
        print("[!] No parseable events found. Check log format.")
        sys.exit(0)

    # ---------------------------------------------------------------
    # Step 2: Detect attacks
    # ---------------------------------------------------------------
    banner("[2/4] Running detectors")
    bf_findings = brute_force.detect(events)
    susp_findings = suspicious_ip.detect(events)
    print(f"  [+] Brute-force findings:   {len(bf_findings)}")
    print(f"  [+] Suspicious IP findings: {len(susp_findings)}")

    # ---------------------------------------------------------------
    # Step 3: Build analysis
    # ---------------------------------------------------------------
    banner("[3/4] Building analysis")
    data = {
        "metadata": {
            "source_file": args.logfile,
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        },
        "summary": build_summary(events),
        "timeline": build_timeline(events),
        "top_ips": top_ips(events),
        "top_users": top_users(events),
        "brute_force": bf_findings,
        "suspicious_ips": susp_findings,
    }
    print(f"  [+] Total events:   {data['summary']['total_events']}")
    print(f"  [+] Unique IPs:     {data['summary']['unique_ips']}")
    print(f"  [+] Unique users:   {data['summary']['unique_users']}")

    # ---------------------------------------------------------------
    # Step 4: Generate report
    # ---------------------------------------------------------------
    banner("[4/4] Generating report")
    out = generate_report(data, output_dir)
    print(f"  [+] Report:  {out}/report.html")
    print(f"  [+] JSON:    {out}/analysis.json")
    print(f"  [+] CSVs:    {out}/events.csv, brute_force.csv")

    banner("DONE")
    print(f"  Analysis completed at {datetime.now().isoformat(timespec='seconds')}")
    print(f"  Open the report: {out}\\report.html\n")


if __name__ == "__main__":
    main()