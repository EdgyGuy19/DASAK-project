from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import Event, Alert    

router = APIRouter(prefix="/api/stats", tags=["stats"])


def in_period(stmt, column, start, end):
    if start is not None:
        stmt = stmt.where(column >= start)
    if end is not None:
        stmt = stmt.where(column <= end)
    return stmt


@router.get("")
def get_stats(
    start: Optional[str] = None,
    end: Optional[str] = None,
    interval: str = Query("hour", pattern="^(hour|day)$"),
    db: Session = Depends(get_db),
):
    total_events = db.scalar(
        in_period(select(func.count()).select_from(Event), Event.timestamp, start, end)
    )
    total_alerts = db.scalar(
            in_period(select(func.count()).select_from(Alert), Alert.timestamp, start, end)
        )

    login_rows = db.execute(
        in_period(
            select(Event.event_type, func.count())
            .where(Event.event_type.in_(["login", "login_failed"]))
            .group_by(Event.event_type),
            Event.timestamp, start, end,
        )
    ).all()
    logins = dict(login_rows)

    fmt = "%Y-%m-%dT%H:00" if interval == "hour" else "%Y-%m-%d"
    bucket = func.strftime(fmt, Event.timestamp)
    time_rows = db.execute(
        in_period(
            select(bucket.label("period"), func.count()).group_by(bucket).order_by(bucket),
            Event.timestamp, start, end,
        )
    ).all()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "logins": {
            "successful": logins.get("login", 0),
            "failed": logins.get("login_failed", 0),
        },
        "severity_counts": None,    # fylls i 
        "events_over_time": [{"period": p, "count": c} for p, c in time_rows],
    }