from __future__ import annotations

from datetime import datetime
from hashlib import sha256


def bucket_for_timestamp(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d-%H")


def build_alert_fingerprint(alert_data: dict) -> str:
    normalized = {
        "rule_name": alert_data.get("rule_name"),
        "host": alert_data.get("host"),
        "user": alert_data.get("user"),
        "source_ip": alert_data.get("source_ip"),
        "time_bucket": bucket_for_timestamp(alert_data["timestamp"]),
    }
    payload = "|".join(str(normalized.get(k, "")) for k in [
        "rule_name",
        "host",
        "user",
        "source_ip",
        "time_bucket",
    ])
    return sha256(payload.encode("utf-8")).hexdigest()
