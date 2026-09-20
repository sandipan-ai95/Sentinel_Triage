from sqlalchemy import func
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert, AnalystDecision, TrainingExample, TriageRecommendation

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("")
def metrics_summary(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    training_examples = db.query(TrainingExample).count()
    average_reward = db.query(func.avg(TrainingExample.reward)).scalar() or 0.0
    recommendation_distribution = {
        recommendation: db.query(TriageRecommendation).filter(TriageRecommendation.recommendation == recommendation).count()
        for recommendation in (
            "high_priority_review",
            "standard_review",
            "low_priority_review",
            "request_enrichment",
            "link_to_existing_incident",
        )
    }
    needs_attention = db.query(Alert).join(
        TriageRecommendation,
        TriageRecommendation.alert_id == Alert.id,
    ).filter(
        Alert.status == "new",
        TriageRecommendation.recommendation.in_(["high_priority_review", "request_enrichment"]),
    ).count()
    severity_breakdown = {
        "critical": db.query(Alert).filter(Alert.severity == "critical").count(),
        "high": db.query(Alert).filter(Alert.severity == "high").count(),
        "medium": db.query(Alert).filter(Alert.severity == "medium").count(),
        "low": db.query(Alert).filter(Alert.severity == "low").count(),
    }
    return {
        "alerts_received": total_alerts,
        "new_alerts": db.query(Alert).filter(Alert.status == "new").count(),
        "needs_attention": needs_attention,
        "analyist_overrides": 0,
        "false_positive_rate": 0.0,
        "triage_latency_seconds": 0,
        "analyst_decisions": db.query(AnalystDecision).count(),
        "training_examples": training_examples,
        "average_reward": round(float(average_reward), 4),
        "recommendation_distribution": recommendation_distribution,
        "severity_breakdown": severity_breakdown,
    }
