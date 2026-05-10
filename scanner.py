#!/usr/bin/env python3
"""
scanner.py — Concurrent port scanner using asyncio + argparse
Part 1 of the security automation lab.
"""

import asyncio
import argparse
import json
import sys
import time
from datetime import datetime


def parse_ports(port_str: str) -> list[int]:
    """Parse port string: supports '22,80,443' and '1-1024' formats."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


async def scan_port(host: str, port: int, semaphore: asyncio.Semaphore, timeout: float) -> tuple[int, bool]:
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return port, False


async def run_scan(host: str, ports: list[int], rate: int, timeout: float) -> list[int]:
    semaphore = asyncio.Semaphore(rate)
    tasks = [scan_port(host, p, semaphore, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(port for port, is_open in results if is_open)


def main():
    parser = argparse.ArgumentParser(description="Async concurrent port scanner")
    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range: '1-1024' or '22,80,443' (default: 1-1024)")
    parser.add_argument("--rate", type=int, default=200,
                        help="Max concurrent connections (default: 200)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("--output", default=None,
                        help="JSON output file (default: stdout)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print(f"[*] Scanning {args.target} — {len(ports)} ports, rate={args.rate}, timeout={args.timeout}s",
          file=sys.stderr)

    start = time.perf_counter()
    open_ports = asyncio.run(run_scan(args.target, ports, args.rate, args.timeout))
    elapsed = time.perf_counter() - start

    result = {
        "target": args.target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": open_ports,
    }

    output_json = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_json)
        print(f"[+] Results saved to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()
