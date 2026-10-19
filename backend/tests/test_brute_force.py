from datetime import datetime, timedelta
from app.database import Base
from app.models import Event
from app.detection.brute_force import detect_brute_force, detect_password_spraying
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import pytest


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def add_event(db, event_id, event_type, username, ip_src, offset_minutes, now):
    db.add(Event(
        event_id=event_id,
        timestamp=now - timedelta(minutes=offset_minutes),
        event_type=event_type,
        username=username,
        ip_src=ip_src,
        status_code=401,
        message="test",
        user_id=0,
        http_request="POST /login",
    ))
    db.commit()


def test_brute_force_triggers_at_threshold(db):
    now = datetime.utcnow()
    for i in range(5):
        add_event(db, i, "login_failed", "admin", "10.0.0.5", i, now)

    results = detect_brute_force(db, now)
    assert len(results) == 1
    assert results[0]["username"] == "admin"
    assert results[0]["event_count"] == 5


def test_brute_force_does_not_trigger_below_threshold(db):
    now = datetime.utcnow()
    for i in range(4):
        add_event(db, i, "login_failed", "admin", "10.0.0.5", i, now)

    results = detect_brute_force(db, now)
    assert results == []


def test_brute_force_ignores_old_events(db):
    now = datetime.utcnow()
    for i in range(5):
        add_event(db, i, "login_failed", "admin", "10.0.0.5", 30 + i, now)  # utanför 5 min

    results = detect_brute_force(db, now)
    assert results == []


def test_password_spraying_triggers(db):
    now = datetime.utcnow()
    for i in range(5):
        add_event(db, i, "login_failed", f"user{i}", "10.0.0.5", i, now)

    results = detect_password_spraying(db, now)
    assert len(results) == 1
    assert results[0]["src_ip"] == "10.0.0.5"