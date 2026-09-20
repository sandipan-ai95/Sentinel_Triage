from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.session import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    raw_summary = Column(Text, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    host = Column(String, nullable=True)
    user = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    asset_criticality = Column(String, nullable=True, default="medium")
    event_count_10m = Column(Integer, default=1)
    related_alert_count_24h = Column(Integer, default=0)
    status = Column(String, default="new")
    raw_event = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True, index=True)
    fingerprint = Column(String, nullable=False, index=True)
    is_deduplicated = Column(Boolean, default=False)

    enrichment = relationship("EnrichmentResult", back_populates="alert", uselist=False)
    recommendations = relationship("TriageRecommendation", back_populates="alert")
    decisions = relationship("AnalystDecision", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    status = Column(String, default="open")
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    related_alerts = relationship("Alert", foreign_keys="Alert.incident_id")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True)
    hostname = Column(String, nullable=False, unique=True)
    criticality = Column(String, default="medium")
    owner = Column(String, nullable=True)
    tags = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), unique=True)
    related_alerts = Column(JSON, default=list)
    event_frequency = Column(Integer, default=0)
    asset_criticality = Column(String, default="medium")
    repeated_source_ips = Column(JSON, default=list)
    prior_incident_history = Column(Integer, default=0)
    prompt_version = Column(String, default="v1")
    created_at = Column(DateTime, default=datetime.utcnow)

    alert = relationship("Alert", back_populates="enrichment")


class TriageRecommendation(Base):
    __tablename__ = "triage_recommendations"

    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=False)
    recommendation = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    policy_version = Column(String, default="v1")
    confidence = Column(Float, default=0.0)
    feature_values = Column(JSON, default=dict)
    probabilities = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    alert = relationship("Alert", back_populates="recommendations")


class AnalystDecision(Base):
    __tablename__ = "analyst_decisions"

    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=False)
    actor = Column(String, nullable=False)
    decision = Column(String, nullable=False)
    previous_value = Column(String, nullable=True)
    new_value = Column(String, nullable=True)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    alert = relationship("Alert", back_populates="decisions")


class PolicyFeedback(Base):
    __tablename__ = "policy_feedback"

    id = Column(String, primary_key=True)
    alert_id = Column(String, nullable=True)
    source = Column(String, default="baseline")
    recommendation = Column(String, nullable=False)
    actual_outcome = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class TrainingExample(Base):
    __tablename__ = "training_examples"

    id = Column(String, primary_key=True)
    alert_id = Column(String, nullable=True)
    state_features = Column(JSON, default=dict)
    action = Column(String, nullable=False)
    reward = Column(Float, default=0.0)
    feature_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
