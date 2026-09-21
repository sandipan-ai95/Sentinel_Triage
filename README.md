# SOC Security Alert Triage Platform

A human-in-the-loop SOC alert triage platform for authorized lab data only. This project is intentionally limited to prioritization, grouping, enrichment, recommendation, and analyst review. It does not implement autonomous blocking, escalation, or remote action execution.

## Demo

<img src="assets/Screen%20Recording%202026-09-21%20at%204.10.31%20PM.gif"
     alt="Sentinel Triage Demo"
     width="1000">

## Dashboard

<img src="assets/Screenshot%202026-09-21%20at%202.45.09%20AM.png"
     alt="Sentinel Triage Dashboard"
     width="1000">


## Safety constraints

- No autonomous containment or blocking
- No firewall changes or account changes
- No remote command execution
- Human review is required for all recommendations
- Raw sensitive data is redacted before external model calls
- OpenRouter secrets remain in environment variables only

## Repository structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/
│   │   ├── config.py
│   │   ├── db/
│   │   ├── models/
│   │   ├── schemas/
│   │   └── services/
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── scripts/
│   ├── replay_alerts.py
│   └── seed_safe_alerts.py
├── data/
│   └── safe_alerts.jsonl
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└──
```

## Quick start

1. Copy `.env.example` to `.env` and configure values.
2. Start infrastructure:

```bash
docker compose up --build
```

3. Run backend tests:

```bash
cd backend && pytest
```
4. Pull current real data from CISA's public Known Exploited Vulnerabilities catalog:

```bash
python scripts/ingest_cisa_kev.py --base-url http://localhost:8000 --limit 10
```

This is a read-only defensive feed. Each CVE is normalized as an alert, triaged locally, and deduplicated by its CVE ID. It does not patch systems or take action against any asset.

5. Seed sample data:

```bash
python scripts/seed_safe_alerts.py
python scripts/replay_alerts.py --path data/safe_alerts.jsonl --delay-seconds 0.2
```

## Architecture

The platform ingests normalized alerts through the FastAPI backend, stores those alerts in PostgreSQL, enriches them with local context, and applies a secure triage recommendation pipeline. The frontend presents an analyst queue, detail pages, and metrics. The system supports local mock triage and can optionally use OpenRouter Jev with a safe redaction layer.

When `OPENROUTER_API_KEY` is set in the backend environment, each new alert is redacted and sent to the configured OpenRouter model for probability scoring. Without a key, the backend uses the local mock provider and records that fallback in the recommendation features. Restart the backend after changing the key; existing alerts are not automatically rescored.

## API examples

### Connecting a real authorized source

The first integration point is a normalized webhook. Configure an authorized SIEM, EDR, or collector to send `POST` requests to `/api/alerts`. The dashboard reads those stored records from `GET /api/alerts`.

Required fields are `timestamp`, `source`, `rule_name`, and `raw_summary`. The remaining fields add triage context:

```json
{
  "timestamp": "2026-09-21T10:00:00Z",
  "source": "your-siem",
  "rule_name": "suspicious_login_pattern",
  "raw_summary": "User login from unusual location.",
  "severity": "high",
  "host": "lab-vpn-01",
  "user": "lab-user",
  "source_ip": "198.51.100.12",
  "destination_ip": "10.0.0.15",
  "asset_criticality": "high",
  "event_count_10m": 3,
  "related_alert_count_24h": 1,
  "status": "new",
  "raw_event": {"provider_event_id": "example-123"}
}
```

For a frontend running against another backend URL, create `frontend/.env.local` with `VITE_API_URL=http://your-backend-host:8000`, then restart Vite. The backend currently accepts normalized events and does not yet include vendor-specific adapters or production authentication; add those before exposing it outside an authorized lab.

```bash
curl -X POST http://localhost:8000/api/alerts \
  -H 'Content-Type: application/json' \
  -d '{
    "timestamp": "2026-09-21T10:00:00Z",
    "source": "auth",
    "rule_name": "suspicious_login_pattern",
    "raw_summary": "User login from unusual location.",
    "severity": "high",
    "host": "vpn-gateway-1",
    "user": "user@example.com",
    "source_ip": "198.51.100.12",
    "destination_ip": "10.0.0.15",
    "asset_criticality": "high",
    "event_count_10m": 3,
    "related_alert_count_24h": 1,
    "status": "new"
  }'
```

## Safety note

This project is for defensive security research in an authorized lab and does not perform autonomous containment or enforcement actions. Every recommendation remains a human-review action only.
