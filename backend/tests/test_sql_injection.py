import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import createAlert, database, eventsLogger
from app.detection.sql_injection import detect_sql_injection
from app.models import Alert, Event, User


@pytest.mark.parametrize("payload", [
    "admin'--",
    "' OR 1=1 --",
    "1 oR 42 = 42",
    "' AND 'abc'='abc' --",
    '" OR "x"="x" --',
    "' OR/**/1=1 --",
    "1 UNION SELECT username, password FROM users",
    "1 UnIoN/**/ALL\nSELECT password FROM users",
    "1 UNION DISTINCT SELECT password FROM users",
    "'; DROP TABLE users --",
    "1; DELETE FROM users",
    "1; INSERT INTO users VALUES (1)",
    "1; UPDATE users SET is_admin=1",
    "1; SELECT password FROM users",
    "' OR SLEEP(5) --",
    "1; SELECT pg_sleep(0.5)",
    "'; WAITFOR DELAY '00:00:05' --",
])
def test_detects_common_signatures(payload):
    assert detect_sql_injection(payload)


@pytest.mark.parametrize("value", [
    "", "alice", "bob", "alice@example.com", "bob@example.com",
    "test-password-123", "select", "union", "drop", "sleep",
    "or 1=2", "or 1=11", "or 'a'='b'",
])
def test_ordinary_inputs_do_not_match(value):
    assert not detect_sql_injection(value)


@pytest.fixture
def client_and_engine(tmp_path, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "sql-injection-test-secret-not-for-production")
    from main import app

    db_file = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    monkeypatch.setattr(database, "engine", engine)
    monkeypatch.setattr(eventsLogger, "DATABASE_FILE", db_file)
    monkeypatch.setattr(createAlert, "DATABASE_FILE", db_file)
    try:
        with TestClient(app) as client:
            yield client, engine
    finally:
        engine.dispose()


def findings(engine):
    with Session(engine) as db:
        events = db.scalars(select(Event).where(Event.event_type == "sql_injection")).all()
        alerts = db.scalars(select(Alert).where(Alert.rule == "sql_injection")).all()
        return events, alerts


def test_login_records_one_event_and_alert_for_multiple_matches(client_and_engine):
    client, engine = client_and_engine
    response = client.post("/login", params={"q": "1 UNION SELECT password FROM users"}, json={
        "username": "' OR 1=1 --", "password": "' OR SLEEP(5) --",
    })
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    events, alerts = findings(engine)
    assert len(events) == len(alerts) == 1
    assert events[0].status_code == 401
    assert events[0].http_request == "POST /login"
    assert events[0].ip_src == alerts[0].ip_src == "testclient"
    assert events[0].message == "Possible SQL injection in query parameters, body.username, body.password"
    assert alerts[0].event_count == 1
    assert alerts[0].status is True
    with Session(engine) as db:
        assert db.scalar(select(Event).where(Event.event_type == "login_failed")) is not None


def test_sql_like_password_is_detected_without_blocking_or_logging_it(client_and_engine):
    client, engine = client_and_engine
    password = "secret-' OR 1=1 --"
    account = {"username": "alice", "email": "alice@example.com", "password": password}
    assert client.post("/register", json=account).status_code == 201
    response = client.post("/login", json=account)
    assert response.status_code == 200
    assert response.json()["access_token"]
    events, alerts = findings(engine)
    assert sorted(event.status_code for event in events) == [200, 201]
    assert len(alerts) == 2
    with Session(engine) as db:
        for row in [*db.scalars(select(Event)), *db.scalars(select(Alert))]:
            for column in row.__table__.columns:
                assert password not in str(getattr(row, column.name))


@pytest.mark.parametrize("field", ["username", "email"])
def test_registration_inspects_fields_even_when_validation_fails(client_and_engine, field):
    client, engine = client_and_engine
    account = {"username": "alice", "email": "alice@example.com", "password": "short"}
    account[field] = "' OR 1=1 --"
    assert client.post("/register", json=account).status_code == 422
    events, alerts = findings(engine)
    assert len(events) == len(alerts) == 1
    assert events[0].status_code == 422
    assert events[0].message == f"Possible SQL injection in body.{field}"


def test_url_encoded_repeated_query_values_are_inspected(client_and_engine):
    client, engine = client_and_engine
    response = client.get("/me?q=ordinary&q=%27%20OR%201%3D1%20--")
    assert response.status_code == 401
    events, alerts = findings(engine)
    assert len(events) == len(alerts) == 1
    assert events[0].http_request == "GET /me"
    assert events[0].message == "Possible SQL injection in query parameters"


@pytest.mark.parametrize("body", [b"{invalid", b"[]", b"null", b'{"username": 1, "password": []}'])
def test_invalid_json_inputs_keep_validation_response(client_and_engine, body):
    client, engine = client_and_engine
    response = client.post("/login", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422
    assert findings(engine) == ([], [])


def test_ordinary_requests_do_not_create_findings(client_and_engine):
    client, engine = client_and_engine
    account = {"username": "bob", "email": "bob@example.com", "password": "normal-password-123"}
    assert client.post("/register", json=account).status_code == 201
    assert client.post("/login", json=account).status_code == 200
    assert client.get("/", params={"q": "union membership"}).status_code == 200
    assert findings(engine) == ([], [])


def test_findings_are_available_through_admin_siem_api(client_and_engine):
    client, engine = client_and_engine
    from app.security import create_access_token

    client.post("/login", json={"username": "' OR 1=1 --", "password": "wrong"})
    with Session(engine) as db:
        admin = User(username="admin", email="admin@example.com", password="unused", is_admin=True)
        db.add(admin)
        db.commit()
        token = create_access_token(admin.id)
    headers = {"Authorization": f"Bearer {token}"}
    events = client.get("/api/siem/events?event_type=sql_injection", headers=headers)
    alerts = client.get("/api/siem/alerts?rule=sql_injection&status=true", headers=headers)
    assert events.status_code == alerts.status_code == 200
    assert len(events.json()) == len(alerts.json()) == 1
    assert events.json()[0]["status_code"] == 401
    assert alerts.json()[0]["rule"] == "sql_injection"
