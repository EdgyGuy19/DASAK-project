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