import re
from datetime import datetime

# This regex matches a standard Nginx/Apache Combined Log Format line.
# Breaking it down:
#   (?P<ip>...)     → named group capturing the IP address
#   (?P<method>...) → HTTP method (GET, POST, etc.)
#   (?P<path>...)   → the requested URL path
#   (?P<status>...) → HTTP response code (200, 404, 500...)
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" '
    r'(?P<status>\d{3})'
)


def parse_log_file(filepath: str) -> list:
    """
    Reads a log file line by line and converts each valid
    line into a structured Python dictionary.
    Invalid or malformed lines are skipped with a warning.
    """
    entries = []

    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue  # skip blank lines

            match = LOG_PATTERN.match(line)
            if match:
                entries.append({
                    "ip": match.group("ip"),
                    "time": match.group("time"),
                    "method": match.group("method"),
                    "path": match.group("path"),
                    "status": int(match.group("status")),
                    "raw": line
                })
            else:
                print(f"[Parser] Line {line_num} did not match expected format — skipped")

    print(f"[Parser] Parsed {len(entries)} valid log entries")
    return entries