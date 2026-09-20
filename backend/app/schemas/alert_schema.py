from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class AlertCreate(BaseModel):
    id: Optional[str] = None
    timestamp: datetime
    source: str
    rule_name: str
    raw_summary: str
    severity: str = "medium"
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    asset_criticality: Optional[str] = "medium"
    event_count_10m: int = 1
    related_alert_count_24h: int = 0
    status: str = "new"
    raw_event: Optional[Dict[str, Any]] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if value.lower() not in allowed:
            raise ValueError("severity must be low, medium, high, or critical")
        return value.lower()

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {"new", "triaged", "in_review", "resolved"}
        if value.lower() not in allowed:
            raise ValueError("status must be new, triaged, in_review, or resolved")
        return value.lower()


class AlertBulkPayload(BaseModel):
    alerts: Optional[List[AlertCreate]] = None
    payload: Optional[List[AlertCreate]] = None


class AlertOut(AlertCreate):
    id: str
    fingerprint: Optional[str] = None
    is_deduplicated: bool = False
