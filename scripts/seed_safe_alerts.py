#!/usr/bin/env python3
import json
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "safe_alerts.jsonl"
OUT.parent.mkdir(parents=True, exist_ok=True)

samples = [
    {
        "id": "alt-001",
        "timestamp": (datetime.utcnow() - timedelta(minutes=4)).isoformat(),
        "source": "identity",
        "rule_name": "multiple_auth_failures",
        "raw_summary": "Multiple failed logins from one source for a low-risk workstation.",
        "severity": "medium",
        "host": "workstation-23",
        "user": "sara.jones",
        "source_ip": "198.51.100.8",
        "destination_ip": "10.0.0.23",
        "asset_criticality": "low",
        "event_count_10m": 7,
        "related_alert_count_24h": 0,
        "status": "new",
        "raw_event": {"action": "login_failed", "login_attempts": 7},
    },
    {
        "id": "alt-002",
        "timestamp": (datetime.utcnow() - timedelta(minutes=18)).isoformat(),
        "source": "auth",
        "rule_name": "suspicious_login_pattern",
        "raw_summary": "User authenticated from two regions in a short period.",
        "severity": "high",
        "host": "vpn-gateway-1",
        "user": "m.chen",
        "source_ip": "203.0.113.42",
        "destination_ip": "10.0.0.88",
        "asset_criticality": "high",
        "event_count_10m": 2,
        "related_alert_count_24h": 2,
        "status": "new",
        "raw_event": {"country_list": ["us", "de"], "travel_velocity": "high"},
    },
    {
        "id": "alt-003",
        "timestamp": (datetime.utcnow() - timedelta(minutes=40)).isoformat(),
        "source": "network",
        "rule_name": "unusual_dns_activity",
        "raw_summary": "Repeated DNS queries to domains not commonly used by the host.",
        "severity": "medium",
        "host": "db-server-12",
        "user": "svc-db-sync",
        "source_ip": "10.0.0.12",
        "destination_ip": "172.16.10.12",
        "asset_criticality": "high",
        "event_count_10m": 18,
        "related_alert_count_24h": 1,
        "status": "new",
        "raw_event": {"dns_queries": 18, "domain_category": "anomalous"},
    },
    {
        "id": "alt-004",
        "timestamp": (datetime.utcnow() - timedelta(minutes=12)).isoformat(),
        "source": "endpoint",
        "rule_name": "malware_like_behavior",
        "raw_summary": "Scheduled task spawned suspicious command pattern on a user workstation.",
        "severity": "critical",
        "host": "endpoint-77",
        "user": "a.nguyen",
        "source_ip": "10.0.0.77",
        "destination_ip": "198.51.100.15",
        "asset_criticality": "critical",
        "event_count_10m": 5,
        "related_alert_count_24h": 3,
        "status": "new",
        "raw_event": {"process_name": "powershell.exe", "command_pattern": "encoded_payload"},
    },
    {
        "id": "alt-005",
        "timestamp": (datetime.utcnow() - timedelta(minutes=7)).isoformat(),
        "source": "policy",
        "rule_name": "policy_violation",
        "raw_summary": "Privileged export operation performed outside approved maintenance window.",
        "severity": "high",
        "host": "finance-db",
        "user": "r.taylor",
        "source_ip": "10.10.50.9",
        "destination_ip": "10.0.0.44",
        "asset_criticality": "critical",
        "event_count_10m": 1,
        "related_alert_count_24h": 0,
        "status": "new",
        "raw_event": {"policy": "export_restriction", "window": "maintenance_only"},
    },
]

with OUT.open("w", encoding="utf-8") as fh:
    for entry in samples:
        fh.write(json.dumps(entry) + "\n")

print(f"Wrote {len(samples)} safe sample alerts to {OUT}")
