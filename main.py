import os
from sentinel.sentinel_event import SentinelEvent
from sentinel.database import save_events, load_events
from sentinel.net_monitor import scan_ports
from sentinel.integrity_check import create_baseline, check_integrity
from sentinel.parser import parse_log_file
from sentinel.sanitizer import scan_entries
from sentinel.threat_engine import calculate_risk_score

# Files to monitor for tampering. Create these dummy files first.
WATCHED_FILES = [
    os.path.join("data", "baseline.json"),
    os.path.join("data", "sample.log"),
]

LOG_FILE = os.path.join("data", "sample.log")


def run():
    print("\n" + "="*50)
    print("   SENTINEL FULL-STACK MONITOR — Starting")
    print("="*50 + "\n")

    all_events = []

    # --- Module 1: Network scan ---
    print(">>> Running network scan...")
    net_events = scan_ports(host="127.0.0.1", port_range=range(1, 1025))
    all_events.extend(net_events)

    # --- Module 2: File integrity check ---
    print("\n>>> Running integrity check...")
    # First run: set the baseline; subsequent runs: check against it
    if not os.path.exists(os.path.join("data", "baseline.json")):
        print("[Main] First run — creating baseline...")
        create_baseline(WATCHED_FILES)
    integrity_events = check_integrity()
    all_events.extend(integrity_events)

    # --- Module 3: Log analysis ---
    print("\n>>> Parsing and scanning log file...")
    if os.path.exists(LOG_FILE):
        log_entries = parse_log_file(LOG_FILE)
        app_events = scan_entries(log_entries)
        all_events.extend(app_events)

    # --- Module 4: Threat engine ---
    print("\n>>> Running threat engine...")
    report = calculate_risk_score(all_events)

    # --- Save everything ---
    save_events(all_events)

    # --- Final report ---
    print("\n" + "="*50)
    print(f"   RISK SCORE : {report['score']} / 100")
    print(f"   LEVEL      : {report['level']}")
    print(f"   SUMMARY    : {report['summary']}")
    print(f"   TOTAL EVENTS: {len(all_events)}")
    print("="*50 + "\n")


if __name__ == "__main__":
    run()
