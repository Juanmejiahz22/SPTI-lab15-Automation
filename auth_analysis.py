#!/usr/bin/env python3
"""
auth_analysis.py — SSH auth log analyzer.
Part 3A of the security automation lab.
"""

import re
import argparse
from collections import defaultdict, Counter


def analyze_auth_log(log_file: str) -> dict:
    failed_by_ip = defaultdict(int)
    failed_by_user = Counter()
    success_count = 0
    fail_count = 0

    failed_re = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port"
    )
    success_re = re.compile(r"Accepted \S+ for (\S+) from")

    with open(log_file) as f:
        for line in f:
            m = failed_re.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1
                fail_count += 1
                continue
            m = success_re.search(line)
            if m:
                success_count += 1

    # IPs with more than 10 failed attempts, sorted desc
    suspicious_ips = sorted(
        [(ip, count) for ip, count in failed_by_ip.items() if count > 10],
        key=lambda x: x[1], reverse=True
    )

    ratio = fail_count / success_count if success_count > 0 else float("inf")

    return {
        "suspicious_ips": suspicious_ips,
        "targeted_users": failed_by_user.most_common(),
        "fail_count": fail_count,
        "success_count": success_count,
        "fail_to_success_ratio": round(ratio, 2),
    }


def print_report(data: dict) -> str:
    lines = []
    lines.append("## SSH Auth Log Analysis\n")
    lines.append(f"Total failed attempts: {data['fail_count']}")
    lines.append(f"Total successful logins: {data['success_count']}")
    lines.append(f"Failed/Success ratio: {data['fail_to_success_ratio']}\n")

    lines.append("### Suspicious IPs (>10 failed attempts)")
    for ip, count in data["suspicious_ips"]:
        lines.append(f"  {ip:20s} {count} attempts")

    lines.append("\n### Targeted usernames")
    for user, count in data["targeted_users"]:
        lines.append(f"  {user:20s} {count} attempts")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH auth logs")
    parser.add_argument("--input", default="auth.log")
    args = parser.parse_args()

    data = analyze_auth_log(args.input)
    report = print_report(data)
    print(report)
    return data


if __name__ == "__main__":
    main()
