import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


EVENT_TYPES = frozenset({
    "registration",
    "login",
    "logout",
    "access",
    "login_fail",
    "login_failed",
    "registration_fail",
    "unauthorized_access",
    "forbidden_access",
    "sql_injection",
    "xss_attempt",
})

DATABASE_FILE = Path(__file__).resolve().parents[2] / "dasak.db"


def log_event(
    event_type: str,
    status_code: int,
    message: str,
    user_id: int | None = None,
    username: str | None = None,
    ip_src: str | None = None,
    http_request: str | None = None,
) -> None:

    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown security event type: {event_type}")

    if type(status_code) is not int or not 100 <= status_code <= 599:
        raise ValueError("status_code must be an integer between 100 and 599")

    data = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "username": username,
        "ip_src": ip_src,
        "http_request": http_request,
        "status_code": status_code,
        "message": message,
    }

    with closing(sqlite3.connect(DATABASE_FILE, timeout=10)) as connection:
        with connection:
            connection.execute("""
                INSERT INTO events (
                    event_id, timestamp, event_type, user_id, username,
                    ip_src, http_request, status_code, message
                ) VALUES (
                    :event_id, :timestamp, :event_type, :user_id, :username,
                    :ip_src, :http_request, :status_code, :message
                )
            """, data)
