from __future__ import annotations

import json
from uuid import uuid4
from datetime import datetime
from typing import Any, List

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import AnalystDecision, Alert, EnrichmentResult, Incident, PolicyFeedback, TrainingExample, TriageRecommendation
from app.schemas.alert_schema import AlertBulkPayload, AlertCreate
from app.services.fingerprint import build_alert_fingerprint
from app.services.redaction import redact_alert_for_model
from app.services.triage import triage_alert
from app.config import get_settings

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AnalystDecisionRequest(BaseModel):
    actor: str = Field(default="analyst.local", min_length=1, max_length=120)
    decision: str = Field(min_length=1, max_length=80)
    reason: str = Field(default="Analyst reviewed the recommendation.", max_length=1000)


@router.get("/health")
def list_alert_health():
    return {"status": "ok"}


@router.get("")
def list_alerts(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    records = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
    response = []
    for alert in records:
        recommendation = (
            db.query(TriageRecommendation)
            .filter(TriageRecommendation.alert_id == alert.id)
            .order_by(TriageRecommendation.created_at.desc())
            .first()
        )
        response.append({
            "id": alert.id,
            "timestamp": alert.timestamp,
            "source": alert.source,
            "rule_name": alert.rule_name,
            "raw_summary": alert.raw_summary,
            "severity": alert.severity,
            "host": alert.host,
            "user": alert.user,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "asset_criticality": alert.asset_criticality,
            "event_count_10m": alert.event_count_10m,
            "related_alert_count_24h": alert.related_alert_count_24h,
            "status": alert.status,
            "fingerprint": alert.fingerprint,
            "recommendation": recommendation.recommendation if recommendation else "standard_review",
            "confidence": recommendation.confidence if recommendation else 0.0,
            "recommendation_reason": recommendation.reason if recommendation else "Awaiting triage.",
            "probabilities": recommendation.probabilities if recommendation else {},
            "model_provider": (recommendation.feature_values or {}).get("model_provider", "unknown") if recommendation else "unknown",
            "model_error": (recommendation.feature_values or {}).get("model_error") if recommendation else None,
            "analyst_decision": (alert.decisions[-1].decision if alert.decisions else None),
            "effective_recommendation": (
                "high_priority_review" if alert.decisions and alert.decisions[-1].decision == "escalate_incident"
                else recommendation.recommendation if recommendation else "standard_review"
            ),
            "vulnerability": {
                key: alert.raw_event.get(key)
                for key in ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate", "knownRansomwareCampaignUse")
                if alert.raw_event and alert.raw_event.get(key) is not None
            } if alert.source == "cisa-kev" else {},
        })
    return response


@router.post("", response_model=dict)
def create_alert(alert: AlertCreate, x_ingest_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    configured_key = get_settings().ingest_api_key
    if configured_key and x_ingest_key != configured_key:
        raise HTTPException(status_code=401, detail="Invalid ingestion key")
    payload = alert.model_dump()
    fingerprint = build_alert_fingerprint(payload)
    existing = db.query(Alert).filter(Alert.fingerprint == fingerprint).first()
    if existing:
        existing.is_deduplicated = True
        db.commit()
        return {"status": "deduplicated", "id": existing.id, "fingerprint": fingerprint}

    alert_id = payload.get("id") or f"alert-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    alert_record = Alert(
        id=alert_id,
        timestamp=payload["timestamp"],
        source=payload["source"],
        rule_name=payload["rule_name"],
        raw_summary=payload["raw_summary"],
        severity=payload["severity"],
        host=payload["host"],
        user=payload["user"],
        source_ip=payload["source_ip"],
        destination_ip=payload["destination_ip"],
        asset_criticality=payload.get("asset_criticality") or "medium",
        event_count_10m=payload.get("event_count_10m", 1),
        related_alert_count_24h=payload.get("related_alert_count_24h", 0),
        status=payload.get("status", "new"),
        raw_event=payload.get("raw_event"),
        fingerprint=fingerprint,
    )
    db.add(alert_record)
    db.commit()
    db.refresh(alert_record)

    triage_alert(db, alert_record)
    return {"status": "accepted", "id": alert_record.id, "fingerprint": fingerprint}


@router.post("/{alert_id}/decisions", response_model=dict)
def record_analyst_decision(alert_id: str, payload: AnalystDecisionRequest, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    recommendation = (
        db.query(TriageRecommendation)
        .filter(TriageRecommendation.alert_id == alert_id)
        .order_by(TriageRecommendation.created_at.desc())
        .first()
    )
    if not recommendation:
        raise HTTPException(status_code=409, detail="Alert has no triage recommendation")

    recommended_action = recommendation.recommendation
    agreement_actions = {
        "high_priority_review": "approve_recommendation",
        "standard_review": "approve_recommendation",
        "low_priority_review": "approve_recommendation",
        "request_enrichment": "request_enrichment",
        "link_to_existing_incident": "escalate_incident",
    }
    reward = 1.0 if payload.decision == agreement_actions.get(recommended_action) else -1.0
    decision_id = f"decision-{uuid4().hex}"

    db.add(AnalystDecision(
        id=decision_id,
        alert_id=alert_id,
        actor=payload.actor,
        decision=payload.decision,
        previous_value=recommended_action,
        new_value=payload.decision,
        reason=payload.reason,
    ))
    db.add(PolicyFeedback(
        id=f"feedback-{uuid4().hex}",
        alert_id=alert_id,
        source="analyst",
        recommendation=recommended_action,
        actual_outcome=payload.decision,
    ))
    db.add(TrainingExample(
        id=f"training-{uuid4().hex}",
        alert_id=alert_id,
        state_features={
            "severity": alert.severity,
            "asset_criticality": alert.asset_criticality,
            "probabilities": recommendation.probabilities or {},
            "model_provider": (recommendation.feature_values or {}).get("model_provider"),
        },
        action=payload.decision,
        reward=reward,
        feature_hash=alert.fingerprint,
    ))
    alert.status = "in_review" if payload.decision == "escalate_incident" else "triaged"
    db.commit()
    return {
        "status": "recorded",
        "alert_id": alert_id,
        "decision_id": decision_id,
        "recommended_action": recommended_action,
        "analyst_action": payload.decision,
        "reward": reward,
    }


@router.post("/bulk", response_model=dict)
def bulk_create_alerts(payload: dict | list, x_ingest_key: str | None = Header(default=None), db: Session = Depends(get_db)):
    if isinstance(payload, list):
        alerts = payload
    elif isinstance(payload, dict) and "alerts" in payload:
        alerts = payload["alerts"]
    elif isinstance(payload, dict) and "payload" in payload:
        alerts = payload["payload"]
    else:
        raise HTTPException(status_code=400, detail="Bulk payload must be a list or object with alerts/payload")

    created = []
    for item in alerts:
        alert = AlertCreate.model_validate(item)
        created.append(create_alert(alert, x_ingest_key, db)["id"])

    return {"status": "accepted", "count": len(created), "ids": created}


@router.post("/replay")
def replay_alerts(file_path: str = Query(...), delay_seconds: float = 0.2, db: Session = Depends(get_db)):
    import subprocess

    script = ["python", "scripts/replay_alerts.py", "--path", file_path, "--delay-seconds", str(delay_seconds)]
    subprocess.Popen(script)
    return {"status": "started", "file": file_path, "delay_seconds": delay_seconds}
