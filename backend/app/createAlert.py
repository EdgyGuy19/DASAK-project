import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

DATABASE_FILE = Path(__file__).resolve().parents[2] / "dasak.db"

def log_alert(
    rule: str,
    event_count: int,
    status: bool,
    message: str,
    username: str | None = None,
    ip_src: str | None = None,
) -> None:
    data = {
        "alert_id": str(uuid4()),
        "username": username,
        "timestamp": datetime.now(timezone.utc),
        "rule": rule,
        "ip_src": ip_src,
        "event_count": event_count,
        "status": status,
        "message": message,
    }
    with closing(sqlite3.connect(DATABASE_FILE, timeout=10)) as connection:
        with connection:
            connection.execute("""
                INSERT INTO alerts (
                    alert_id, username, timestamp, rule, ip_src, event_count, status, message
                ) VALUES (
                    :alert_id, :username, :timestamp, :rule, :ip_src, :event_count, :status, :message
                )
            """, data)

