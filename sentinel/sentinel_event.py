from datetime import datetime, timezone

class SentinelEvent:
    """
    The universal data structure every module must use.
    Think of it as the 'envelope' all findings get packaged into
    before being sent to the central engine.
    """

    def __init__(self, event_type: str, source: str, severity: int, description: str):
        # datetime.now(timezone.utc) gives a timezone-aware timestamp
        # .isoformat() formats it as "2025-04-25T14:32:00+00:00" — the forensic standard
        self.timestamp = datetime.now(timezone.utc).isoformat()

        # event_type tells us WHERE the event came from
        # Must be exactly one of: "Network", "System", "Application"
        self.event_type = event_type

        # source is the specific origin — an IP address, a file path, or a log entry
        self.source = source

        # severity is a 1–5 integer scale: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
        self.severity = severity

        # description is plain English — what actually happened
        self.description = description

    def to_dict(self) -> dict:
        """Converts the event to a dictionary so it can be saved as JSON."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity,
            "description": self.description
        }

    def __repr__(self):
        """This controls what you see when you print() an event — useful for debugging."""
        return (f"[{self.severity}] {self.event_type} | {self.source} | "
                f"{self.description} @ {self.timestamp}")