"""
Brute Force Detector
=====================
Detects brute-force attacks from log events:
  - Groups failed login attempts by IP
  - Flags IPs exceeding a threshold within a time window
  - Identifies target usernames

Heuristic: if an IP has >= THRESHOLD failed attempts within WINDOW_MINUTES,
it is flagged as a brute-force attack.
"""

from collections import defaultdict, Counter
from datetime import datetime


THRESHOLD = 5          # failed attempts to consider brute force
WINDOW_MINUTES = 10    # time window


def _parse_iso(ts):
    """Parse ISO timestamp string. Returns datetime or None."""
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def detect(events):
    """
    Detect brute-force attacks from a list of parsed events.
    Returns list of findings sorted by severity.
    """
    # Group failed attempts by IP
    by_ip = defaultdict(list)

    for e in events:
        if e["event_type"] in ("failed_password", "invalid_user"):
            ip = e.get("ip", "").strip()
            if ip:
                by_ip[ip].append(e)

    findings = []

    for ip, attempts in by_ip.items():
        if len(attempts) < THRESHOLD:
            continue

        # Time window analysis
        timestamps = [_parse_iso(a["timestamp"]) for a in attempts]
        timestamps = [t for t in timestamps if t]
        timestamps.sort()

        # Find dense windows
        peak_count = 0
        window_start = None
        window_end = None

        for i in range(len(timestamps)):
            window_start_i = timestamps[i]
            count = 1
            last = window_start_i
            for j in range(i + 1, len(timestamps)):
                delta = (timestamps[j] - window_start_i).total_seconds() / 60
                if delta <= WINDOW_MINUTES:
                    count += 1
                    last = timestamps[j]
                else:
                    break
            if count > peak_count:
                peak_count = count
                window_start = window_start_i
                window_end = last

        # Target usernames
        usernames = Counter(a["user"] for a in attempts if a.get("user"))

        # Severity
        if peak_count >= 20:
            severity = "CRITICAL"
        elif peak_count >= 10:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        findings.append({
            "ip": ip,
            "total_attempts": len(attempts),
            "peak_attempts_in_window": peak_count,
            "window_minutes": WINDOW_MINUTES,
            "first_seen": timestamps[0].isoformat(timespec="seconds") if timestamps else "",
            "last_seen": timestamps[-1].isoformat(timespec="seconds") if timestamps else "",
            "target_usernames": usernames.most_common(5),
            "severity": severity,
        })

    # Sort by peak attempts (highest first)
    findings.sort(key=lambda x: x["peak_attempts_in_window"], reverse=True)

    return findings