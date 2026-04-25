import hashlib
import json
import os
from sentinel.sentinel_event import SentinelEvent

BASELINE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'baseline.json')


def hash_file(filepath: str) -> str:
    """
    Reads a file in binary chunks and returns its SHA-256 hash.
    Reading in chunks (8192 bytes at a time) means large files
    won't consume all your RAM at once.
    """
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):   # walrus operator — read AND assign in one step
            sha256.update(chunk)
    return sha256.hexdigest()           # returns a 64-character hex string


def create_baseline(filepaths: list) -> None:
    """
    Takes a list of file paths, hashes each one, and saves
    the results as the 'known good' baseline.
    Run this ONCE when the system is in a trusted state.
    """
    baseline = {}
    for path in filepaths:
        if os.path.exists(path):
            baseline[path] = hash_file(path)
            print(f"[Integrity] Baseline set for: {path}")
        else:
            print(f"[Integrity] WARNING — file not found: {path}")

    with open(BASELINE_PATH, 'w') as f:
        json.dump(baseline, f, indent=2)


def check_integrity() -> list:
    events = []

    if not os.path.exists(BASELINE_PATH):
        print("[Integrity] No baseline found. Run create_baseline() first.")
        return events

    with open(BASELINE_PATH, 'r') as f:
        content = f.read().strip()
        # If the file is empty, treat it as no baseline yet
        if not content:
            print("[Integrity] Baseline file is empty. Run create_baseline() first.")
            return events
        baseline = json.loads(content)

    # ... rest of function stays the same

    for path, original_hash in baseline.items():
        if not os.path.exists(path):
            # File has been deleted — that's critical
            event = SentinelEvent(
                event_type="System",
                source=path,
                severity=5,
                description=f"Monitored file DELETED: {path}"
            )
            events.append(event)
        else:
            current_hash = hash_file(path)
            if current_hash != original_hash:
                # File content has changed since baseline
                event = SentinelEvent(
                    event_type="System",
                    source=path,
                    severity=4,
                    description=f"File integrity violation: {path}"
                )
                events.append(event)
                print(f"[Integrity] CHANGED → {path}")

    return events