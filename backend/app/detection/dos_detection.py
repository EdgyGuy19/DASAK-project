import sqlite3
import asyncio
from collections import defaultdict
from contextlib import closing
from pathlib import Path
from fastapi import Request
from starlette.concurrency import run_in_threadpool
from ..eventsLogger import log_event
from ..createAlert import log_alert

DATABASE_FILE = Path(__file__).resolve().parents[3] / "dasak.db"
REQUEST_THRESHOLD = 100
WINDOW_SECONDS = 20
ALERT_COOLDOWN_SECONDS = 120
CHECK_INTERVAL_SECONDS = 5

def check_dos_attack():
    with (
        closing(sqlite3.connect(DATABASE_FILE, timeout=10)) as connection,
        connection,
    ):
        quory_event = connection.execute(f"""
            SELECT event_id, timestamp, event_type, user_id, username,
                   ip_src, http_request, status_code, message
            FROM events
            WHERE event_type = 'http_request'
              AND julianday(timestamp)
                  BETWEEN julianday('now', '-{WINDOW_SECONDS} seconds')
                      AND julianday('now')
        """)
        quory_alert = connection.execute(f"""
            SELECT ip_src, timestamp FROM alerts
            WHERE status = TRUE
              AND rule = 'DOS Attack'
              AND julianday(timestamp)
                  BETWEEN julianday('now', '-{ALERT_COOLDOWN_SECONDS} seconds')
                      AND julianday('now')
        """)
        events = quory_event.fetchall()
        existing_alerts = quory_alert.fetchall()

    if not events:
        return

    filtered_events = event_filter(events)

    for ip_src, ip_events in filtered_events.items():
        if len(ip_events) < REQUEST_THRESHOLD:
            continue

        matching_alerts = []

        for alert in existing_alerts:
            if alert[0] == ip_src:
                matching_alerts.append(alert)
        if matching_alerts:
            continue

        log_alert(
            rule="DOS Attack",
            username=ip_events[0][4],
            event_count=len(ip_events),
            status=True,
            message="Possible DOS attack detected",
            ip_src=ip_src
        )


async def log_dos_request(request: Request, call_next):
    response = await call_next(request)

    await run_in_threadpool(
        log_event,
        event_type="http_request",
        status_code=response.status_code,
        message="HTTP request",
        ip_src=request.client.host if request.client else None,
        http_request=f"{request.method} {request.url.path}",
    )

    return response

async def run_dos_detection():
    while True:
        try:
            await run_in_threadpool(check_dos_attack)
        except Exception as error:
            print(f"DoS check failed: {error}")

        await asyncio.sleep(CHECK_INTERVAL_SECONDS)

def event_filter(events):
    groups_by_ip = defaultdict(list)
    for event in events:
        groups_by_ip[event[5]].append(event)
    return groups_by_ip
