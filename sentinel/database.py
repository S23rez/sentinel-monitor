import json
import os

# This is where all events get saved. Using a relative path keeps
# the project portable — it works on any machine.
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'events.json')


def save_events(events: list) -> None:
    """
    Saves a list of SentinelEvent objects to a JSON file.
    Each event is first converted to a dict via .to_dict().
    """
    # Convert all event objects to plain dictionaries
    data = [event.to_dict() for event in events]

    # 'w' mode overwrites the file each time (a full snapshot)
    # indent=2 makes the JSON human-readable
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"[DB] Saved {len(events)} event(s) to {DB_PATH}")


def load_events() -> list:
    """
    Loads previously saved events from the JSON file.
    Returns a list of dictionaries (not SentinelEvent objects).
    """
    # If no events have been saved yet, return an empty list
    if not os.path.exists(DB_PATH):
        return []

    with open(DB_PATH, 'r') as f:
        return json.load(f)