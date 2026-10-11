"""
Linux auth.log Parser
======================
Parses /var/log/auth.log (and similar SSH auth logs) and extracts:
  - Successful logins (Accepted password/publickey)
  - Failed login attempts (Failed password)
  - Invalid user attempts
  - Sudo commands
  - Session opened/closed
"""

import re
from datetime import datetime


# --------------------------------------------------------------------
# Regex patterns for auth.log entries
# --------------------------------------------------------------------

PATTERNS = {
    "failed_password": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    "accepted_password": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
        r"Accepted password for (?P<user>\S+) "
        r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
    ),
    "invalid_user": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "sudo_command": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sudo:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.+)"
    ),
    "session_opened": re.compile(
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
        r"pam_unix\(sshd:session\):\s+session opened for user (?P<user>\S+)"
    ),
}


def _normalize_timestamp(ts_str):
    """Convert 'Oct 11 22:15:03' to ISO format 'YYYY-10-11T22:15:03'."""
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        return dt.isoformat(timespec="seconds")
    except ValueError:
        return ts_str


def parse_line(line):
    """Parse a single log line. Returns dict or None."""
    line = line.strip()
    if not line:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            data = match.groupdict()
            return {
                "event_type": event_type,
                "timestamp": _normalize_timestamp(data.get("timestamp", "")),
                "user": data.get("user", ""),
                "ip": data.get("ip", ""),
                "port": data.get("port", ""),
                "command": data.get("command", ""),
                "raw": line,
            }
    return None


def parse_file(filepath):
    """Parse an entire auth.log file. Returns list of events."""
    events = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events