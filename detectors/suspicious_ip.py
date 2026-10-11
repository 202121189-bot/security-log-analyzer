"""
Suspicious IP Detector
=======================
Flags IPs with suspicious patterns:
  - High ratio of failed to successful logins
  - Attempts on multiple users (user enumeration)
  - Attempts on non-existent users (invalid user)
  - Known-bad IPs (from a small built-in blocklist)

Note: For real deployments, replace the blocklist with a threat-intel feed.
"""

from collections import defaultdict


# --------------------------------------------------------------------
# Small built-in blocklist (for demo purposes)
# Add known-bad IPs here, or load from a file.
# --------------------------------------------------------------------
BLOCKLIST = {
    # Public examples only — replace with your own threat intel
    "185.220.101.0",
    "45.155.205.0",
    "80.82.77.0",
    "5.188.206.0",
}


def _is_in_blocklist(ip):
    """Check if IP is in the blocklist (basic match)."""
    return ip in BLOCKLIST


def detect(events):
    """
    Analyze events and return list of suspicious IPs with reasons.
    """
    by_ip = defaultdict(lambda: {
        "failed": 0,
        "success": 0,
        "invalid_user": 0,
        "targets": set(),
        "first_seen": None,
        "last_seen": None,
    })

    for e in events:
        ip = e.get("ip", "").strip()
        if not ip:
            continue

        entry = by_ip[ip]
        ts = e.get("timestamp", "")
        if ts:
            if entry["first_seen"] is None or ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if entry["last_seen"] is None or ts > entry["last_seen"]:
                entry["last_seen"] = ts

        et = e["event_type"]
        if et == "failed_password":
            entry["failed"] += 1
            if e.get("user"):
                entry["targets"].add(e["user"])
        elif et == "accepted_password":
            entry["success"] += 1
        elif et == "invalid_user":
            entry["invalid_user"] += 1
            if e.get("user"):
                entry["targets"].add(e["user"])

    findings = []

    for ip, data in by_ip.items():
        reasons = []
        score = 0

        total_auth = data["failed"] + data["success"]

        # Rule 1: many failed attempts
        if data["failed"] >= 10:
            reasons.append(f"{data['failed']} failed login attempts")
            score += 30
        elif data["failed"] >= 5:
            reasons.append(f"{data['failed']} failed login attempts")
            score += 15

        # Rule 2: high failure ratio (and at least 5 attempts)
        if total_auth >= 5 and data["failed"] / total_auth >= 0.8:
            reasons.append(
                f"{int(data['failed'] / total_auth * 100)}% failure rate"
            )
            score += 20

        # Rule 3: multiple distinct targets (enumeration)
        if len(data["targets"]) >= 5:
            reasons.append(f"{len(data['targets'])} distinct target users (enumeration)")
            score += 25

        # Rule 4: invalid user attempts
        if data["invalid_user"] >= 3:
            reasons.append(f"{data['invalid_user']} invalid user attempts")
            score += 20

        # Rule 5: blocklisted IP
        if _is_in_blocklist(ip):
            reasons.append("IP is in the threat-intel blocklist")
            score += 50

        if score >= 20:
            if score >= 60:
                severity = "CRITICAL"
            elif score >= 40:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            findings.append({
                "ip": ip,
                "score": min(score, 100),
                "severity": severity,
                "failed": data["failed"],
                "success": data["success"],
                "invalid_user": data["invalid_user"],
                "distinct_targets": len(data["targets"]),
                "first_seen": data["first_seen"] or "",
                "last_seen": data["last_seen"] or "",
                "reasons": reasons,
            })

    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings