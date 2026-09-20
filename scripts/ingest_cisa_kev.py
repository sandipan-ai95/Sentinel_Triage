#!/usr/bin/env python3
"""Ingest recent CISA KEV records as normalized alerts."""

import argparse
import os
from datetime import datetime, timezone

import httpx

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def severity_for(record: dict) -> str:
    return "critical" if record.get("knownRansomwareCampaignUse") == "Known" else "high"


def to_alert(record: dict) -> dict:
    added = record.get("dateAdded")
    timestamp = f"{added}T00:00:00Z" if added else datetime.now(timezone.utc).isoformat()
    return {
        "id": f"cisa-kev-{record['cveID']}",
        "timestamp": timestamp,
        "source": "cisa-kev",
        "rule_name": "known_exploited_vulnerability",
        "raw_summary": f"{record['vulnerabilityName']} affects {record['vendorProject']} {record['product']}",
        "severity": severity_for(record),
        "host": None,
        "user": None,
        "source_ip": None,
        "destination_ip": None,
        "asset_criticality": "high",
        "event_count_10m": 1,
        "related_alert_count_24h": 0,
        "status": "new",
        "raw_event": record,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Pull live CISA KEV records into the local triage API.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--limit", type=int, default=10, help="Number of newest CISA records to ingest")
    args = parser.parse_args()

    with httpx.Client(timeout=30.0) as client:
        feed = client.get(FEED_URL)
        feed.raise_for_status()
        records = feed.json().get("vulnerabilities", [])
        records.sort(key=lambda record: record.get("dateAdded", ""), reverse=True)

            headers = {}
            if os.getenv("INGEST_API_KEY"):
                headers["X-Ingest-Key"] = os.environ["INGEST_API_KEY"]
        for record in records[: max(1, args.limit)]:
            alert = to_alert(record)
                response = client.post(f"{args.base_url.rstrip('/')}/api/alerts", json=alert, headers=headers)
            response.raise_for_status()
            print(f"{alert['id']} -> {response.json().get('status')}")


if __name__ == "__main__":
    main()
