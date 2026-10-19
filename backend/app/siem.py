from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import Alert, Event
from .schemas import AlertOut, AlertStatusUpdate, EventOut

router = APIRouter(prefix="/api/siem", tags=["siem"])


@router.get("/events", response_model=list[EventOut])
def list_events(
    event_type: str | None = None,
    username: str | None = None,
    ip_src: str | None = None,
    status_code: int | None = Query(default=None, ge=100, le=599),
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(Event)
    if event_type is not None:
        statement = statement.where(Event.event_type == event_type)
    if username is not None:
        statement = statement.where(Event.username == username)
    if ip_src is not None:
        statement = statement.where(Event.ip_src == ip_src)
    if status_code is not None:
        statement = statement.where(Event.status_code == status_code)
    statement = statement.order_by(func.julianday(Event.timestamp).desc(), Event.event_id.desc())
    return db.scalars(statement.offset(offset).limit(limit)).all()


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: str, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    rule: str | None = None,
    status: bool | None = None,
    username: str | None = None,
    ip_src: str | None = None,
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    statement = select(Alert)
    if rule is not None:
        statement = statement.where(Alert.rule == rule)
    if status is not None:
        statement = statement.where(Alert.status == status)
    if username is not None:
        statement = statement.where(Alert.username == username)
    if ip_src is not None:
        statement = statement.where(Alert.ip_src == ip_src)
    statement = statement.order_by(func.julianday(Alert.timestamp).desc(), Alert.id.desc())
    return db.scalars(statement.offset(offset).limit(limit)).all()


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert_status(alert_id: str, data: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = get_alert(alert_id, db)
    alert.status = data.status
    db.commit()
    db.refresh(alert)
    return alert
