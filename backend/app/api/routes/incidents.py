from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.alert import Alert, Incident

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    return {"items": [{
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "summary": incident.summary,
    } for incident in incidents]}


@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"status": "not_found"}
    return {"incident": {
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "summary": incident.summary,
        "alerts": [
            {"id": alert.id, "rule_name": alert.rule_name, "severity": alert.severity}
            for alert in incident.related_alerts
        ],
    }}
