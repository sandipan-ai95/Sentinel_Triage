from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TriageProbability(BaseModel):
    likely_false_positive: float = 0.0
    needs_immediate_escalation: float = 0.0
    needs_more_context: float = 0.0
    likely_related_to_existing_incident: float = 0.0
    likely_requires_human_review: float = 1.0


class RecommendationCreate(BaseModel):
    decision_id: Optional[str] = None
    alert_id: str
    recommendation: str
    reason: str
    policy_version: str = "v1"
    confidence: float = 0.0
    feature_values: Dict[str, Any] = Field(default_factory=dict)
    probabilities: Dict[str, float] = Field(default_factory=dict)


class DecisionAudit(BaseModel):
    actor: str
    decision: str
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    reason: str
