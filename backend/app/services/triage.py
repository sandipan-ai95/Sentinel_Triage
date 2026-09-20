from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.alert import Alert, AnalystDecision, EnrichmentResult, TriageRecommendation
from app.services.redaction import redact_alert_for_model
from app.services.openrouter_provider import OpenRouterJevProvider

ALLOWED_RECOMMENDATIONS = {
    "high_priority_review",
    "standard_review",
    "low_priority_review",
    "request_enrichment",
    "link_to_existing_incident",
}


def _enrich_alert(db: Session, alert: Alert) -> Dict[str, Any]:
    related = db.query(Alert).filter(
        Alert.source == alert.source,
        Alert.host == alert.host,
        Alert.user == alert.user,
        Alert.timestamp >= alert.timestamp,
    ).count()

    result = EnrichmentResult(
        id=f"enrich-{alert.id}",
        alert_id=alert.id,
        related_alerts=[{"id": alert.id, "rule_name": alert.rule_name}],
        event_frequency=max(alert.event_count_10m, 1),
        asset_criticality=alert.asset_criticality or "medium",
        repeated_source_ips=[alert.source_ip] if alert.source_ip else [],
        prior_incident_history=related,
        prompt_version="v1",
    )
    db.add(result)
    db.commit()
    return {
        "related_alerts": result.related_alerts,
        "event_frequency": result.event_frequency,
        "asset_criticality": result.asset_criticality,
        "repeated_source_ips": result.repeated_source_ips,
        "prior_incident_history": result.prior_incident_history,
    }


def _mock_jev_probabilities(alert: Alert) -> Dict[str, float]:
    severity_weight = {"low": 0.1, "medium": 0.25, "high": 0.45, "critical": 0.65}[alert.severity.lower()]
    asset_weight = {"low": 0.05, "medium": 0.2, "high": 0.35, "critical": 0.5}[alert.asset_criticality.lower()]
    base = min(0.9, max(0.05, severity_weight + asset_weight + (0.1 if alert.event_count_10m > 5 else 0)))
    return {
        "likely_false_positive": round(max(0.0, 0.35 - base), 4),
        "needs_immediate_escalation": round(min(0.99, max(0.1, base * 0.7)), 4),
        "needs_more_context": round(min(0.99, max(0.15, 0.55 - base * 0.6)), 4),
        "likely_related_to_existing_incident": round(min(0.99, max(0.1, base * 0.8)), 4),
        "likely_requires_human_review": round(min(0.99, max(0.55, base + 0.2)), 4),
    }


def _recommendation_from_probabilities(probabilities: Dict[str, float], asset_criticality: str, severity: str) -> Dict[str, Any]:
    if severity.lower() == "critical":
        rec = "high_priority_review"
        reason = "Critical-severity alert requires human review regardless of baseline confidence."
    elif probabilities["needs_immediate_escalation"] >= 0.7 and asset_criticality.lower() in {"high", "critical"}:
        rec = "high_priority_review"
        reason = "Escalation probability is high and asset criticality warrants heightened analyst attention."
    elif probabilities["needs_more_context"] >= 0.7:
        rec = "request_enrichment"
        reason = "The alert has significant uncertainty and needs additional context before disposition."
    elif probabilities["likely_related_to_existing_incident"] >= 0.6:
        rec = "link_to_existing_incident"
        reason = "The alert is likely related to an existing grouping and should be reviewed with context."
    elif probabilities["likely_false_positive"] >= 0.6:
        rec = "low_priority_review"
        reason = "Likelihood of false positive is elevated, but the alert remains visible for analyst confirmation."
    else:
        rec = "standard_review"
        reason = "The alert is within normal analyst triage flow with human review required."

    if rec not in ALLOWED_RECOMMENDATIONS:
        rec = "standard_review"
    return {"recommendation": rec, "reason": reason, "confidence": max(probabilities.values())}


def triage_alert(db: Session, alert: Alert) -> Dict[str, Any]:
    context = _enrich_alert(db, alert)
    model_input = {
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "source": alert.source,
        "raw_summary": alert.raw_summary,
        "host": alert.host,
        "user": alert.user,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "asset_criticality": alert.asset_criticality,
        "event_count_10m": alert.event_count_10m,
        "related_alert_count_24h": alert.related_alert_count_24h,
    }
    safe_alert = redact_alert_for_model(model_input)
    provider = OpenRouterJevProvider(
        api_key=get_settings().openrouter_api_key,
        model=get_settings().openrouter_model,
    )
    probabilities = provider.get_probabilities(model_input)

    recommendation = _recommendation_from_probabilities(probabilities, alert.asset_criticality or "medium", alert.severity)
    rec = TriageRecommendation(
        id=f"rec-{alert.id}",
        alert_id=alert.id,
        recommendation=recommendation["recommendation"],
        reason=recommendation["reason"],
        policy_version="v1",
        confidence=recommendation["confidence"],
        feature_values={
            **context,
            "source": alert.source,
            "severity": alert.severity,
            "model_provider": provider.last_source,
            "model_error": provider.last_error,
        },
        probabilities=probabilities,
    )
    db.add(rec)
    db.commit()
    return {
        "alert_id": alert.id,
        "recommendation": recommendation,
        "probabilities": probabilities,
        "redacted_alert": safe_alert,
    }
