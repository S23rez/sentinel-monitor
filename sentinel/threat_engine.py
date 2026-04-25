from sentinel.sentinel_event import SentinelEvent


def calculate_risk_score(events: list) -> dict:
    """
    Analyses a combined list of SentinelEvents from all modules.
    Returns a risk report with a 0–100 score and a summary.

    The scoring logic:
    - Base score = sum of all event severities
    - Bonus multiplier if events span multiple types (cross-domain attack)
    - Critical individual events push the score up hard
    - Final score is clamped to 100
    """
    if not events:
        return {"score": 0, "level": "Clean", "summary": "No events detected."}

    # Add up all severities
    base_score = sum(e.severity for e in events)

    # Check how many different event types appeared
    types_seen = {e.event_type for e in events}

    # If threats span multiple domains (network + application + system),
    # that's a coordinated attack pattern — escalate the score
    multiplier = 1.0
    if len(types_seen) == 2:
        multiplier = 1.3
    elif len(types_seen) == 3:
        multiplier = 1.6

    # Check for any critical (severity 5) events — immediate escalation
    has_critical = any(e.severity == 5 for e in events)
    critical_bonus = 20 if has_critical else 0

    final_score = min(int(base_score * multiplier) + critical_bonus, 100)

    # Assign a human-readable risk level
    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 55:
        level = "HIGH"
    elif final_score >= 30:
        level = "MEDIUM"
    elif final_score >= 10:
        level = "LOW"
    else:
        level = "INFO"

    summary = (f"{len(events)} event(s) across {', '.join(types_seen)}. "
               f"Multiplier: {multiplier}x. Critical events: {has_critical}.")

    return {"score": final_score, "level": level, "summary": summary}