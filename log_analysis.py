#!/usr/bin/env python3
"""
log_analysis.py — Web access log analyzer with anomaly detection.
Part 3C-E of the security automation lab.
"""

import re
import argparse
import math
from collections import defaultdict, Counter
from datetime import datetime


# Attack pattern regexes
ATTACK_PATTERNS = {
    "sql_injection": re.compile(
        r"(union\s+select|'\s*(or|and)\s*'?\d|--|;\s*drop|1=1|sleep\(|benchmark\()",
        re.IGNORECASE
    ),
    "path_traversal": re.compile(r"\.\./|\.\.%2[fF]|%2e%2e"),
    "xss": re.compile(r"<script|javascript:|onerror=|onload=|alert\(", re.IGNORECASE),
    "cmd_injection": re.compile(r"cmd=|exec=|system\(|;\s*id\b|;\s*ls\b|\$\(", re.IGNORECASE),
}

LOG_RE = re.compile(
    r'([\d.]+) - - \[(\d{2}/\w+/\d{4}):(\d{2}):\d{2}:\d{2}[^\]]*\] "(\w+) ([^"]+) HTTP[^"]*" (\d{3})'
)


def parse_access_log(log_file: str):
    entries = []
    with open(log_file) as f:
        for line in f:
            m = LOG_RE.match(line)
            if m:
                entries.append({
                    "ip": m.group(1),
                    "hour": int(m.group(3)),
                    "method": m.group(4),
                    "path": m.group(5),
                    "status": int(m.group(6)),
                    "raw": line.strip(),
                })
    return entries


def detect_attacks(entries: list) -> list:
    hits = []
    for e in entries:
        for attack_type, pattern in ATTACK_PATTERNS.items():
            if pattern.search(e["path"]):
                hits.append({**e, "attack_type": attack_type})
                break
    return hits


def top_ips(entries: list, n: int = 5) -> list:
    counts = Counter(e["ip"] for e in entries)
    return counts.most_common(n)


def status_distribution(entries: list) -> dict:
    counts = Counter(e["status"] for e in entries)
    return dict(sorted(counts.items()))


def zscore_anomalies(entries: list, threshold: float = 3.0) -> list:
    hourly = Counter(e["hour"] for e in entries)
    counts = [hourly.get(h, 0) for h in range(24)]

    mean = sum(counts) / len(counts)
    variance = sum((x - mean) ** 2 for x in counts) / len(counts)
    std = math.sqrt(variance) if variance > 0 else 1

    anomalies = []
    for hour, count in enumerate(counts):
        z = (count - mean) / std
        if abs(z) >= threshold:
            anomalies.append({"hour": hour, "count": count, "zscore": round(z, 2)})
    return anomalies


def generate_report(auth_data: dict, access_entries: list, attacks: list,
                    top_ip_list: list, status_dist: dict, anomalies: list) -> str:
    lines = ["# Security Log Analysis Report\n"]

    # Auth section
    lines.append("## 1. SSH Authentication Analysis")
    lines.append(f"- Failed login attempts: {auth_data['fail_count']}")
    lines.append(f"- Successful logins: {auth_data['success_count']}")
    lines.append(f"- Fail/Success ratio: {auth_data['fail_to_success_ratio']}")
    lines.append("\n**Suspicious IPs (>10 failures):**")
    for ip, count in auth_data["suspicious_ips"]:
        lines.append(f"- `{ip}`: {count} attempts")
    lines.append("\n**Targeted usernames:**")
    for user, count in auth_data["targeted_users"]:
        lines.append(f"- `{user}`: {count} attempts")

    # Attack patterns
    lines.append("\n## 2. Detected Attack Patterns")
    if attacks:
        for a in attacks:
            lines.append(f"- [{a['attack_type'].upper()}] `{a['path']}` from `{a['ip']}` → HTTP {a['status']}")
    else:
        lines.append("- No attack patterns detected.")

    # Top IPs
    lines.append("\n## 3. Top IPs by Request Volume")
    for ip, count in top_ip_list:
        lines.append(f"- `{ip}`: {count} requests")

    # Status codes
    lines.append("\n## 4. HTTP Status Code Distribution")
    for code, count in status_dist.items():
        lines.append(f"- {code}: {count} responses")

    # Anomalies
    lines.append("\n## 5. Hourly Traffic Anomalies (3σ detector)")
    if anomalies:
        for a in anomalies:
            lines.append(f"- [ANOMALY] {a['hour']:02d}:00 — {a['count']} requests (z={a['zscore']}σ, threshold=3.0σ)")
    else:
        lines.append("- No anomalous hours detected.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze web access logs")
    parser.add_argument("--input", default="access.log")
    parser.add_argument("--auth", default="auth.log")
    parser.add_argument("--output", default="report.md")
    args = parser.parse_args()

    # Import auth analysis inline
    import auth_analysis
    auth_data = auth_analysis.analyze_auth_log(args.auth)

    entries = parse_access_log(args.input)
    attacks = detect_attacks(entries)
    top_ip_list = top_ips(entries)
    status_dist = status_distribution(entries)
    anomalies = zscore_anomalies(entries)

    # Print anomalies to console
    for a in anomalies:
        print(f"[ANOMALY] {a['hour']:02d}:00 — {a['count']} requests (z={a['zscore']}σ, threshold=3.0σ)")

    report = generate_report(auth_data, entries, attacks, top_ip_list, status_dist, anomalies)

    with open(args.output, "w") as f:
        f.write(report)
    print(f"\n[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
