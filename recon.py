#!/usr/bin/env python3
"""
recon.py — Integrated multi-stage reconnaissance tool.
Part 4 of the security automation lab.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


# ── Audit log ──────────────────────────────────────────────────────────────

def make_audit_logger(log_path: str):
    def log(action: str, result: str):
        ts = datetime.now().isoformat(timespec="seconds")
        with open(log_path, "a") as f:
            f.write(f"[{ts}] ACTION: {action}\n")
            f.write(f"[{ts}] RESULT: {result}\n\n")
    return log


# ── Subprocess helper ──────────────────────────────────────────────────────

def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = r.stdout + r.stderr
        return True, output.strip()
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)


# ── Domain mode ────────────────────────────────────────────────────────────

def run_whois_domain(target: str, audit) -> dict:
    ok, out = run_cmd(["whois", target])
    audit(f"whois {target}", "ok" if ok else "error")
    if not ok:
        return {"error": out}

    result = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"(?:Registrar Registration Expiration Date|Registry Expiry Date):\s*(.+)",
        "organization": r"Registrant Organization:\s*(.+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, out, re.IGNORECASE)
        result[key] = m.group(1).strip() if m else None
    return result


def run_dig(target: str, audit) -> dict:
    records = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        ok, out = run_cmd(["dig", "+short", rtype, target])
        audit(f"dig {rtype} {target}", "ok" if ok else "error")
        records[rtype] = out.splitlines() if ok and out else []
    return records


def run_curl_headers(target: str, audit) -> dict:
    ok, out = run_cmd(["curl", "-I", "-L", "--max-time", "10",
                        f"https://{target}"], timeout=15)
    if not ok:
        ok, out = run_cmd(["curl", "-I", "-L", "--max-time", "10",
                            f"http://{target}"], timeout=15)
    audit(f"curl -I {target}", "ok" if ok else "error")

    headers = {}
    interesting = ["server", "x-powered-by", "content-security-policy",
                   "strict-transport-security", "x-frame-options"]
    for line in out.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            k = key.strip().lower()
            if k in interesting:
                headers[k] = val.strip()
    return headers


# ── IP mode ────────────────────────────────────────────────────────────────

def run_nmap(target: str, xml_path: str, audit) -> list:
    ok, out = run_cmd(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", xml_path, target],
        timeout=120
    )
    audit(f"nmap -sV --open --top-ports 100 {target}", "ok" if ok else f"error: {out}")
    if not ok or not os.path.exists(xml_path):
        return []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports = []
        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port_elem.get("portid"))
                svc = port_elem.find("service")
                service_name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                ports.append({
                    "port": port_num,
                    "service": service_name,
                    "version": f"{product} {version}".strip(),
                })
        return ports
    except Exception as e:
        audit("parse nmap xml", f"error: {e}")
        return []


def run_reverse_dns(target: str, audit) -> list:
    ok, out = run_cmd(["dig", "-x", target, "+short"])
    audit(f"dig -x {target}", "ok" if ok else "error")
    return out.splitlines() if ok and out else []


def run_whois_ip(target: str, audit) -> dict:
    ok, out = run_cmd(["whois", target])
    audit(f"whois {target}", "ok" if ok else "error")
    if not ok:
        return {"error": out}

    result = {}
    for key, pattern in [
        ("organization", r"(?:OrgName|org-name|owner):\s*(.+)"),
        ("country", r"(?:Country|country):\s*(.+)"),
    ]:
        m = re.search(pattern, out, re.IGNORECASE)
        result[key] = m.group(1).strip() if m else None
    return result


# ── Report generator ────────────────────────────────────────────────────────

def generate_markdown(target: str, mode: str, results: dict) -> str:
    lines = [f"# Recon Report: {target}", f"**Mode:** {mode}",
             f"**Generated:** {datetime.now().isoformat(timespec='seconds')}\n"]

    lines.append("## Summary Table")
    lines.append("| Tool | Status |")
    lines.append("|------|--------|")
    for tool, data in results.items():
        status = "✅ OK" if data and "error" not in str(data)[:30] else "❌ Error/Empty"
        lines.append(f"| {tool} | {status} |")

    if mode == "domain":
        if "whois" in results:
            lines.append("\n## WHOIS Information")
            for k, v in results["whois"].items():
                lines.append(f"- **{k}**: {v}")

        if "dns" in results:
            lines.append("\n## DNS Records")
            for rtype, records in results["dns"].items():
                lines.append(f"**{rtype}:** {', '.join(records) if records else 'none'}")

        if "headers" in results:
            lines.append("\n## HTTP Headers")
            headers = results["headers"]
            for k, v in headers.items():
                lines.append(f"- `{k}`: {v}")

            lines.append("\n### Missing Security Headers")
            required = {
                "content-security-policy": "CSP",
                "strict-transport-security": "HSTS",
                "x-frame-options": "X-Frame-Options",
            }
            for header, name in required.items():
                if header not in headers:
                    lines.append(f"- ⚠️ **{name}** is missing")

    elif mode == "ip":
        if "open_ports" in results:
            lines.append("\n## Open Ports")
            lines.append("| Port | Service | Version |")
            lines.append("|------|---------|---------|")
            for p in results["open_ports"]:
                lines.append(f"| {p['port']} | {p['service']} | {p['version']} |")

        if "reverse_dns" in results:
            lines.append("\n## Reverse DNS")
            lines.append(", ".join(results["reverse_dns"]) or "No PTR records found")

        if "whois" in results:
            lines.append("\n## IP WHOIS")
            for k, v in results["whois"].items():
                lines.append(f"- **{k}**: {v}")

    return "\n".join(lines)


# ── Main ────────────────────────────────────────────────────────────────────

def detect_mode(target: str) -> str:
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return "ip" if ip_re.match(target) else "domain"


def main():
    parser = argparse.ArgumentParser(description="Integrated recon tool")
    parser.add_argument("target", help="Domain name or IP address")
    parser.add_argument("--mode", choices=["domain", "ip"],
                        help="Force mode (auto-detected if omitted)")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: ./recon_<target>_<timestamp>/)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress to stderr")
    args = parser.parse_args()

    mode = args.mode or detect_mode(args.target)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = args.target.replace("/", "_").replace(".", "_")
    out_dir = args.output or f"./recon_{safe_target}_{ts}"
    os.makedirs(out_dir, exist_ok=True)

    audit_path = os.path.join(out_dir, "audit.log")
    audit = make_audit_logger(audit_path)
    audit(f"recon.py started: target={args.target} mode={mode}", "init")

    def vprint(msg: str):
        if args.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    results = {}

    if mode == "domain":
        vprint("Running whois...")
        results["whois"] = run_whois_domain(args.target, audit)

        vprint("Running dig (A, MX, NS, TXT)...")
        results["dns"] = run_dig(args.target, audit)

        vprint("Fetching HTTP headers...")
        results["headers"] = run_curl_headers(args.target, audit)

    else:  # ip mode
        xml_path = os.path.join(out_dir, "scan.xml")
        vprint("Running nmap...")
        results["open_ports"] = run_nmap(args.target, xml_path, audit)

        vprint("Running reverse DNS lookup...")
        results["reverse_dns"] = run_reverse_dns(args.target, audit)

        vprint("Running whois on IP...")
        results["whois"] = run_whois_ip(args.target, audit)

    # Write results.json
    results_path = os.path.join(out_dir, "results.json")
    with open(results_path, "w") as f:
        json.dump({"target": args.target, "mode": mode,
                   "timestamp": ts, "results": results}, f, indent=2)
    vprint(f"Saved results.json")

    # Write report.md
    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w") as f:
        f.write(generate_markdown(args.target, mode, results))
    vprint(f"Saved report.md")

    audit("recon.py finished", f"output_dir={out_dir}")
    print(f"\n[+] Done! Output in: {out_dir}")
    print(f"    - {results_path}")
    print(f"    - {report_path}")
    print(f"    - {audit_path}")


if __name__ == "__main__":
    main()
