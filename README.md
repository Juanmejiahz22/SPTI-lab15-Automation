# Security Automation Lab — Submission

## Python version and dependencies

Tested on: **Python 3.11** (Kali Linux 2024.x)

All scripts use only the Python standard library. No additional pip packages required.

System tools required (pre-installed on Kali Linux):

```bash
sudo apt install -y nmap whois dnsutils curl openssh-client
```

No `pip install` needed.

---

## Part 1 — `scanner.py` : Concurrent port scanner

### What it does

Performs concurrent TCP port scanning using `asyncio` + `asyncio.Semaphore`. Supports both comma-separated port lists (`22,80,443`) and ranges (`1-1024`). Results are output as JSON to stdout or a file.

### How to run

```bash
# Basic scan of localhost
python3 scanner.py 127.0.0.1

# Custom port range
python3 scanner.py 127.0.0.1 --ports 22,80,443,8080

# With output file
python3 scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --timeout 0.5 --output results.json

# Test different concurrency levels
python3 scanner.py 127.0.0.1 --rate 50
python3 scanner.py 127.0.0.1 --rate 200
python3 scanner.py 127.0.0.1 --rate 500
```

### Performance comparison (sequential vs asyncio)

| Mode | Concurrency | Time |
|------|-------------|------|
| Sequential (baseline) | 1 | 0.0s |
| asyncio | 50 | 0.10s |
| asyncio | 200 | 0.12s |
| asyncio | 500 | 0.11s |

### Screenshot — Sequential baseline vs asyncio results

[IMAGEN 1]

### Design choices

`asyncio` was chosen over `ThreadPoolExecutor` because it avoids OS thread overhead and scales better at high concurrency. `asyncio.Semaphore` provides a clean, configurable cap on simultaneous connections without spawning extra threads. The `--ports` parser handles both comma-separated lists and dash ranges in a single pass.

---

## Part 2 — `parse_scan.py` : nmap XML parser and SSH enricher

### What it does

Reads the XML output of an nmap scan, extracts structured data (IP, hostname, open ports, service versions) for each live host, and enriches hosts that have port 22 open by running `ssh-keyscan` to retrieve the host key type. Results are written to `hosts.json`.

### How to run

```bash
# Step 1 — generate scan.xml
sudo nmap -sV --open -oX scan.xml 192.168.64.134/24

# Step 2 — parse and enrich
python3 parse_scan.py --input scan.xml --output hosts.json
```

### Screenshot — hosts.json output

[IMAGEN 2]

### Design choices

Uses only `xml.etree.ElementTree` from the standard library as required. SSH enrichment runs `ssh-keyscan` via `subprocess` with an explicit timeout so an unresponsive host never blocks execution. Each host is enriched independently; an error on one does not affect the others.

---

## Part 3 — `auth_analysis.py` : SSH auth log analyzer

### What it does

Parses an SSH auth log (`auth.log`) to identify: IPs with more than 10 failed login attempts (sorted descending), usernames being targeted by brute force, and the overall failed-to-successful login ratio.

### How to run

```bash
python3 auth_analysis.py --input auth.log
```

### Design choices

Single-pass parsing using `re`, `collections.Counter`, and `defaultdict`. The regex handles both `"Failed password for user"` and `"Failed password for invalid user user"` formats. Imported by `log_analysis.py` to combine outputs into a unified report.

---

## Part 3 — `log_analysis.py` : Web log analyzer + anomaly detection

### What it does

Reads an Apache-format `access.log` and produces: detected attack patterns (SQL injection, path traversal, XSS, command injection), top 5 IPs by request volume, HTTP status code distribution, and 3-sigma anomaly detection on hourly traffic. Combines all findings with auth log analysis into a single `report.md`.

### How to run

```bash
python3 log_analysis.py --input access.log --auth auth.log --output report.md
```

### Screenshot — Attack detection + anomaly detector output

[IMAGEN 3]

### Design choices

Attack detection uses a dictionary of precompiled regexes for easy extensibility. The 3-sigma detector computes mean and standard deviation over 24 hourly buckets and flags any hour with |z| >= 3.0. Importing `auth_analysis` directly avoids code duplication.

---

## Part 4 — `recon.py` : Integrated reconnaissance tool

### What it does

Single-file CLI tool that performs multi-stage reconnaissance on a domain or IP. In domain mode: runs `whois`, `dig` (A/MX/NS/TXT records), and `curl -I` for HTTP headers. In IP mode: runs `nmap -sV`, reverse DNS via `dig -x`, and `whois`. Outputs `results.json`, `report.md`, and a mandatory `audit.log` timestamping every action.

### How to run

```bash
# Domain mode (auto-detected)
sudo python3 recon.py scanme.nmap.org --verbose

# IP mode (auto-detected)
sudo python3 recon.py 45.33.32.156 --verbose --output ./sample_output

# Force mode and custom output directory
sudo python3 recon.py scanme.nmap.org --mode domain --output ./my_recon --verbose
```

### Screenshot — recon.py full run (domain + IP mode)

[IMAGEN 4]

### Design choices

Each tool (whois, dig, curl, nmap) is wrapped in an independent try/except so a failure in one step never crashes the tool. The audit log is written before and after every action with ISO timestamps. Mode is auto-detected by matching the target against an IPv4 regex. `results.json` always contains structured parsed data (dicts/lists), never raw text blobs. Missing security headers (CSP, HSTS, X-Frame-Options) are explicitly flagged in `report.md`.

---

## Answers to lab questions

### Part 1 — False negatives at high concurrency

At very high concurrency (e.g. `--rate 2000`), the local OS exhausts available file descriptors or ephemeral ports. Connection attempts fail with `OSError: Too many open files` or similar errors, which the scanner catches and records as "port closed" — even when the port is genuinely open. This means "the scanner did not detect it" is not the same as "the port is closed": it only means the scanner's own resource exhaustion caused the probe to fail, not that the remote service rejected it. The same principle applies to nmap: results of "closed" or "filtered" can also reflect firewall drops, probe rate limits, or packet loss. Scan results are probabilistic evidence, not ground truth, and should always be interpreted with an awareness of the scanner's own limitations.

### Part 2 — Version banners and security

A banner like `Apache httpd 2.4.54` immediately tells an attacker which CVEs apply. They can query the NVD for that exact version, find unpatched vulnerabilities, and proceed directly to exploitation without guesswork. A server returning no version string forces the attacker to fingerprint blindly or try exploits speculatively — both take more time and generate more detectable noise. Banner suppression (e.g. `ServerTokens Prod` in Apache) is not a complete defense, but it meaningfully raises the cost of targeted attacks and is trivial to configure.

### Part 3 — 3-sigma and daily periodicity

A single global mean over 24 hours is statistically invalid when traffic has strong daily cycles: daytime hours will consistently read as anomalously high while overnight hours read as anomalously low, flooding analysts with false positives. A better approach is to compute a separate baseline per hour-of-day slot using historical data — for example, a rolling 7-day average for each individual hour. An anomaly is then defined relative to what is normal for that specific hour, not the overall daily mean. This is called hour-of-day normalization and is standard practice in SIEM alerting rules.

### Part 4 — Active vs passive reconnaissance

Active reconnaissance (this tool, nmap) sends packets directly to the target. Every probe can be logged by the target's firewall, IDS, or WAF: the attacker's IP appears in server logs and may trigger rate-limit or signature-based alerts. Passive reconnaissance (Shodan) queries a pre-built database — no packet ever reaches the target, making it effectively undetectable by any network monitor the defender has in place. Active recon is appropriate when you own the target (authorized penetration test) and need live, current data. Passive recon is appropriate for pre-engagement intelligence gathering where stealth is required, or for a quick overview without touching the target.
