import re
from sentinel.sentinel_event import SentinelEvent

# Each entry is a tuple: (pattern, name, severity)
# Patterns are compiled once at import time for efficiency
ATTACK_PATTERNS = [
    (re.compile(r"('|%27).*(OR|AND|SELECT|UNION|INSERT|DROP|--|;)", re.IGNORECASE),
     "SQL Injection", 5),

    (re.compile(r"<script[\s>]|javascript:|onerror\s*=|onload\s*=", re.IGNORECASE),
     "XSS (Cross-Site Scripting)", 4),

    (re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE),
     "Path Traversal", 4),

    (re.compile(r"(wget|curl|bash|sh|cmd|powershell)\s", re.IGNORECASE),
     "Command Injection", 5),
]


def scan_entries(log_entries: list) -> list:
    """
    Takes the list of parsed log dictionaries from parser.py
    and scans the 'path' field of each entry for known attack patterns.
    Returns a list of SentinelEvents for any matches found.
    """
    events = []

    for entry in log_entries:
        path = entry.get("path", "")

        for pattern, attack_name, severity in ATTACK_PATTERNS:
            if pattern.search(path):
                event = SentinelEvent(
                    event_type="Application",
                    source=f"{entry['ip']} → {path}",
                    severity=severity,
                    description=f"{attack_name} pattern detected in request path"
                )
                events.append(event)
                print(f"[Sanitizer] {attack_name} from {entry['ip']}: {path}")
                break  # one event per log line is enough — don't double-count

    return events