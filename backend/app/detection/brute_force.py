from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert
from ..models import Event

FAILED_THRESHOLD = 5
WINDOW_MINUTES = 5

SPRAY_THRESHOLD = 5
SPRAY_WINDOW_MINUTES = 10


def _window_start(now: datetime, minutes: int) -> datetime:
    return now - timedelta(minutes=minutes)


def detect_brute_force(db: Session, now: datetime | None = None) -> list[dict]:
    """Många misslyckade försök mot samma konto."""
    now = now or datetime.utcnow()
    start = _window_start(now, WINDOW_MINUTES)

    rows = db.execute(
        select(Event.username, Event.ip_src)
        .where(Event.event_type == "login_failed")
        .where(Event.timestamp >= start)
    ).all()

    counts: dict[str, dict] = {}
    for username, ip_src in rows:
        if not username:
            continue
        entry = counts.setdefault(username, {"count": 0, "ips": set()})
        entry["count"] += 1
        if ip_src:
            entry["ips"].add(ip_src)

    return [
        {
            "rule": "brute_force_login",
            "severity": "medium",
            "username": username,
            "src_ip": next(iter(data["ips"]), None),
            "event_count": data["count"],
            "message": f"{data['count']} misslyckade inloggningar mot '{username}' på {WINDOW_MINUTES} minuter",
        }
        for username, data in counts.items()
        if data["count"] >= FAILED_THRESHOLD
    ]


def detect_password_spraying(db: Session, now: datetime | None = None) -> list[dict]:
    """Samma IP provar många olika konton."""
    now = now or datetime.utcnow()
    start = _window_start(now, SPRAY_WINDOW_MINUTES)

    rows = db.execute(
        select(Event.ip_src, Event.username)
        .where(Event.event_type == "login_failed")
        .where(Event.timestamp >= start)
    ).all()

    by_ip: dict[str, set] = {}
    for ip_src, username in rows:
        if not ip_src or not username:
            continue
        by_ip.setdefault(ip_src, set()).add(username)

    return [
        {
            "rule": "password_spraying",
            "severity": "medium",
            "username": None,
            "src_ip": ip,
            "event_count": len(usernames),
            "message": f"IP {ip} provade {len(usernames)} olika konton på {SPRAY_WINDOW_MINUTES} minuter",
        }
        for ip, usernames in by_ip.items()
        if len(usernames) >= SPRAY_THRESHOLD
    ]


def run_all(db: Session, now: datetime | None = None) -> list[dict]:
    return detect_brute_force(db, now) + detect_password_spraying(db, now)


def persist_alerts(db: Session, findings: list[dict]) -> None:
    """Saves findings as open alerts, skipping duplicates still open."""
    for f in findings:
        existing = db.scalar(
            select(Alert).where(
                Alert.rule == f["rule"],
                Alert.username == f["username"],
                Alert.status == True,  # noqa: E712
            )
        )
        if existing:
            continue
        db.add(Alert(
            rule=f["rule"],
            username=f["username"],
            ip_src=f["src_ip"],
            event_count=f["event_count"],
            status=True,
            message=f["message"],
        ))
    db.commit()