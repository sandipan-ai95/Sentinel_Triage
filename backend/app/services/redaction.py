from __future__ import annotations

from copy import deepcopy

REDACTION_FIELDS = {"password", "token", "secret", "api_key", "authorization", "cookie", "raw_log"}


def redact_value(value):
    if isinstance(value, str):
        return "[REDACTED]" if value and len(value) > 2 else "[REDACTED]"
    return value


def redact_alert_for_model(alert: dict) -> dict:
    safe = deepcopy(alert)
    if not isinstance(safe, dict):
        return {}

    for key in list(safe.keys()):
        if key.lower() in REDACTION_FIELDS:
            safe[key] = "[REDACTED]"
        elif isinstance(safe[key], dict):
            safe[key] = redact_alert_for_model(safe[key])
        elif isinstance(safe[key], list):
            safe[key] = [redact_alert_for_model(item) if isinstance(item, dict) else redact_value(item) for item in safe[key]]
        elif key.lower() in {"user", "source_ip", "destination_ip", "host"}:
            safe[key] = redact_value(safe[key]) if safe[key] else safe[key]
    return safe
