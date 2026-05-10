#!/usr/bin/env python3
"""
parse_scan.py — Parses nmap XML output, enriches with SSH key info.
Part 2 of the security automation lab.
"""

import xml.etree.ElementTree as ET
import subprocess
import json
import argparse
import sys


def parse_nmap_xml(xml_file: str) -> list[dict]:
    tree = ET.parse(xml_file)
    root = tree.getroot()
    hosts = []

    for host in root.findall("host"):
        # Check host is up
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Get IP
        ip = None
        hostname = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")

        # Get hostname
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        if ip is None:
            continue

        # Get open ports
        open_ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num = int(port_elem.get("portid"))
                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    service_version = f"{product} {version}".strip()
                open_ports.append({
                    "port": port_num,
                    "service": service_name,
                    "version": service_version,
                })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports,
        })

    return hosts


def get_ssh_key_type(ip: str, timeout: int = 5) -> str | None:
    """Run ssh-keyscan and extract the key type."""
    try:
        result = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                return parts[1]  # key type is the second field
        return None
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def enrich_with_ssh(hosts: list[dict]) -> list[dict]:
    for host in hosts:
        port_numbers = [p["port"] for p in host["open_ports"]]
        if 22 in port_numbers:
            print(f"[*] Running ssh-keyscan on {host['ip']}...", file=sys.stderr)
            key_type = get_ssh_key_type(host["ip"])
            host["ssh_host_key_type"] = key_type if key_type else "unavailable"
    return hosts


def main():
    parser = argparse.ArgumentParser(description="Parse nmap XML and enrich with SSH info")
    parser.add_argument("--input", default="scan.xml", help="nmap XML file (default: scan.xml)")
    parser.add_argument("--output", default="hosts.json", help="Output JSON file (default: hosts.json)")
    args = parser.parse_args()

    print(f"[*] Parsing {args.input}...", file=sys.stderr)
    hosts = parse_nmap_xml(args.input)
    print(f"[+] Found {len(hosts)} live hosts", file=sys.stderr)

    hosts = enrich_with_ssh(hosts)

    with open(args.output, "w") as f:
        json.dump(hosts, f, indent=2)

    print(f"[+] Results written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
