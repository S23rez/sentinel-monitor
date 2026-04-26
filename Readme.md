# 🛡️ Project Sentinel — Full-Stack Security Monitor

> A modular, pure-Python security orchestration tool that combines network port scanning,
> file integrity monitoring, and application-level threat detection into a unified
> threat detection engine with real-time risk scoring.

![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red?logo=shield)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Modules](#modules)
- [Sample Output](#sample-output)
- [Getting Started](#getting-started)
- [Risk Scoring](#risk-scoring)
- [Attack Types Detected](#attack-types-detected)
- [What I Learned](#what-i-learned)
- [Next Steps](#next-steps)

---

## Overview

**Project Sentinel** is a solo-built, portfolio-grade security monitoring suite written
entirely in core Python — no external security libraries. It actively probes the local
environment for threats across three security domains simultaneously:

| Domain | What it monitors |
|---|---|
| 🌐 Network | Open TCP ports and suspicious services |
| 🗂️ System | File integrity via SHA-256 cryptographic hashing |
| 📋 Application | Web server logs for injection and traversal attacks |

All findings are packaged into a unified `SentinelEvent` data structure, correlated by
a heuristic threat engine, and scored on a **0–100 Risk Scale**.


---

## Features

- **Port Scanner** — Scans localhost TCP ports 1–1024, flags suspicious services
- **File Integrity Monitor** — SHA-256 baseline hashing, detects modifications and deletions
- **Log Parser** — Normalises raw Nginx/Apache Combined Log Format entries
- **Attack Detector** — Regex-based detection of SQLi, XSS, Path Traversal, Command Injection
- **Threat Engine** — Correlates events across domains, computes unified Risk Score
- **JSON Persistence** — All events saved to `data/events.json` for forensic review
- **Forensic Timestamps** — All events timestamped in ISO 8601 UTC format
- **Zero dependencies** — Built entirely on Python's standard library

---

## Project Structure

```
sentinel-monitor/
│
├── sentinel/                   # Core Python package
│   ├── __init__.py             # Package initialiser
│   ├── sentinel_event.py       # Universal event data structure (shared contract)
│   ├── database.py             # JSON persistence — save/load events
│   ├── net_monitor.py          # TCP port scanner using socket
│   ├── integrity_check.py      # SHA-256 file integrity checker using hashlib
│   ├── parser.py               # Nginx log normaliser using re
│   ├── sanitizer.py            # Attack pattern detector using re
│   └── threat_engine.py        # Heuristic risk scoring engine
│
├── data/
│   ├── baseline.json           # Stored file hash baselines
│   ├── events.json             # All detected security events
│   └── sample.log              # Simulated Nginx access log with attack payloads
│
├── main.py                     # Orchestrator — runs all modules in sequence
├── .gitignore
└── README.md
```

---

## How It Works

```
┌─────────────────────────────────────────────┐
│                   main.py                   │
│              (Orchestrator)                 │
└──────┬──────────┬──────────┬────────────────┘
       │          │          │
       ▼          ▼          ▼
┌──────────┐ ┌─────────┐ ┌──────────────────┐
│net_monitor│ │integrity│ │parser.py →       │
│  .py     │ │_check.py│ │sanitizer.py      │
│(Network) │ │(System) │ │(Application)     │
└──────┬───┘ └────┬────┘ └────────┬─────────┘
       │          │               │
       └──────────┴───────────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │  SentinelEvent[]    │  ← all findings packaged
       └──────────┬──────────┘    into shared schema
                  │
                  ▼
       ┌─────────────────────┐
       │   threat_engine.py  │  ← correlate + score
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │   database.py       │  ← persist to JSON
       └─────────────────────┘
```

Every module outputs `SentinelEvent` objects — a shared data contract with five fields:
`timestamp`, `event_type`, `source`, `severity` (1–5), and `description`.

---

## Modules

### `sentinel_event.py` — The Shared Contract
Defines the `SentinelEvent` class. Every module must package its findings into this
structure before returning them. Ensures all 7 modules speak the same language.

### `database.py` — Storage Layer
Serialises `SentinelEvent` objects to JSON using `json.dump()`. Loads historical
events with `json.load()`. Handles empty/missing files gracefully.

### `net_monitor.py` — Port Scanner
Uses `socket.connect_ex()` to probe TCP ports. Classifies open ports against a
dictionary of suspicious services (FTP, Telnet, SMB, MySQL, Redis, MongoDB, VMware).
Assigns severity 4 to known suspicious ports, severity 2 to unknown open ports.

### `integrity_check.py` — File Integrity Monitor
Hashes files using `hashlib.sha256()` in 8192-byte chunks (memory efficient).
`create_baseline()` stores known-good hashes. `check_integrity()` re-hashes and
compares — any change triggers a `SentinelEvent` with severity 4 (modified) or 5 (deleted).

### `parser.py` — Log File Reader
Uses a compiled regex pattern to parse Nginx/Apache Combined Log Format.
Extracts: IP address, timestamp, HTTP method, request path, and status code.
Malformed lines are skipped with a warning.

### `sanitizer.py` — Attack Pattern Detector
Scans parsed log entries against four compiled regex patterns:
- **SQL Injection** — detects `'`, `%27` followed by SQL keywords (severity 5)
- **XSS** — detects `<script>`, `javascript:`, `onerror=`, `onload=` (severity 4)
- **Path Traversal** — detects `../`, `..\`, `%2e%2e` (severity 4)
- **Command Injection** — detects `wget`, `curl`, `bash`, `powershell` (severity 5)

### `threat_engine.py` — Risk Scoring Engine
Accepts all events and computes a 0–100 risk score using:
1. **Base score** — sum of all event severities
2. **Cross-domain multiplier** — 1.3× for 2 event types, 1.6× for 3
3. **Critical bonus** — +20 if any severity-5 event present
4. **Clamped** to maximum of 100

---

## Sample Output

```
==================================================
   SENTINEL FULL-STACK MONITOR — Starting
==================================================
>>> Running network scan...
[Net] Scanning 127.0.0.1 on ports 1–1024...
[Net] OPEN → 127.0.0.1:135 (Windows RPC) — severity 4
[Net] OPEN → 127.0.0.1:445 (Windows SMB) — severity 4
[Net] OPEN → 127.0.0.1:902 (VMware Auth) — severity 4
[Net] OPEN → 127.0.0.1:912 (VMware Auth) — severity 4
>>> Running integrity check...
>>> Parsing and scanning log file...
[Parser] Parsed 5 valid log entries
[Sanitizer] SQL Injection from 10.0.0.5: /login?user=%27OR%201=1--
[Sanitizer] XSS (Cross-Site Scripting) from 10.0.0.7: /search?q=<script>alert(1)</script>
[Sanitizer] Path Traversal from 192.168.1.99: /../../../../etc/passwd
>>> Running threat engine...
[DB] Saved 7 event(s) to data/events.json
==================================================
   RISK SCORE  : 57 / 100
   LEVEL       : HIGH
   TOTAL EVENTS: 7
==================================================
```

---

## Getting Started

### Prerequisites
- Python 3.8 or higher
- No external packages required

### Installation

```bash
# Clone the repository
git clone https://github.com/S23rez/sentinel-monitor.git

# Navigate into the project
cd sentinel-monitor

# Switch to the develop branch
git checkout develop
```

### Running Sentinel

```bash
python main.py
```

**First run:** Sentinel automatically creates a baseline hash of all watched files
and saves it to `data/baseline.json`.

**Subsequent runs:** Sentinel compares current file hashes against the baseline and
alerts on any changes.

### Customising the scan

In `main.py`, you can adjust:

```python
# Change the scan target and port range
net_events = scan_ports(host="127.0.0.1", port_range=range(1, 1025))

# Change which files are monitored for integrity
WATCHED_FILES = [
    os.path.join("data", "baseline.json"),
    os.path.join("data", "sample.log"),
]
```

---

## Risk Scoring

| Score | Level | Meaning |
|---|---|---|
| 0–9 | INFO | No meaningful threats detected |
| 10–29 | LOW | Minor anomalies, monitoring recommended |
| 30–54 | MEDIUM | Suspicious activity, investigation warranted |
| 55–79 | HIGH | Likely attack attempt, immediate review required |
| 80–100 | CRITICAL | Confirmed attack or active breach |

### Score Calculation Example

With 4 open ports (severity 4 each) + SQL Injection (severity 5) + XSS (severity 4)
+ Path Traversal (severity 4):

```
Base score  = (4×4) + 5 + 4 + 4 = 29
Multiplier  = 1.3× (Network + Application = 2 domains)
After mult  = 29 × 1.3 = 37
Crit bonus  = +20 (SQL Injection is severity 5)
Final score = 57 → HIGH
```

---

## Attack Types Detected

| Attack | Example Payload | Severity | Real-World Impact |
|---|---|---|---|
| SQL Injection | `' OR 1=1--` | 5 — Critical | Full database access, authentication bypass |
| XSS | `<script>alert(1)</script>` | 4 — High | Session hijacking, credential theft |
| Path Traversal | `../../../../etc/passwd` | 4 — High | Read arbitrary server files |
| Command Injection | `; wget malware.sh` | 5 — Critical | Remote code execution |

---

## What I Learned

Building this project solo gave me hands-on understanding of:

- **Python OOP** — designing classes with constructors, methods, and `__repr__`
- **Network programming** — TCP/IP fundamentals, socket connections, port scanning
- **Cryptographic hashing** — SHA-256 file integrity verification from first principles
- **Regular expressions** — pattern compilation, named groups, IGNORECASE flag
- **Security concepts** — SQLi, XSS, Path Traversal, Command Injection from first principles
- **Modular architecture** — decoupled modules communicating through a shared schema
- **Forensic timestamping** — UTC-aware datetimes in ISO 8601 format
- **Git & GitHub workflow** — feature branches, merge conflicts, pull requests, .gitignore

---

## Next Steps

- [ ] Add email alerts via `smtplib` when risk score exceeds threshold
- [ ] CLI argument support via `argparse` (host, port range, log file)
- [ ] Real-time log watching with `watchdog`
- [ ] SQLite storage replacing JSON via `sqlite3`
- [ ] Flask web dashboard for event visualisation
- [ ] Rate-based brute force detection
- [ ] MITRE ATT&CK framework mapping for each detection type
- [ ] Double URL encoding bypass fix (`urllib.parse.unquote` twice)
- [ ] HTML entity decoding bypass fix (`html.unescape`)

---

## Author

**Odunuga Fatai Olayinka** — Cybersecurity Student  
GitHub: [@S23rez](https://github.com/S23rez)

---

*Built with pure Python · No external dependencies · April 2025*
