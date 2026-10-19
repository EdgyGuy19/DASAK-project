import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

os.environ["JWT_SECRET"] = "test-secret-not-used-outside-these-tests-12345"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app import database, eventsLogger
from app.models import User
from app.security import verify_password
from main import app


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.engine = create_engine(
            f"sqlite:///{self.temp.name}/test.db",
            connect_args={"check_same_thread": False},
        )
        self.engine_patch = patch.object(database, "engine", self.engine)
        self.engine_patch.start()
        self.logger_patch = patch.object(eventsLogger, "DATABASE_FILE", Path(self.temp.name) / "test.db")
        self.logger_patch.start()
        self.client = TestClient(app)
        self.client.__enter__()
        self.account = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "test-password-123",
        }

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.engine_patch.stop()
        self.logger_patch.stop()
        self.engine.dispose()
        self.temp.cleanup()

    def register_and_login(self):
        response = self.client.post("/register", json=self.account)
        self.assertEqual(response.status_code, 201)
        response = self.client.post("/login", json=self.account)
        self.assertEqual(response.status_code, 200)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    def test_registration_login_and_me(self):
        headers = self.register_and_login()
        response = self.client.get("/me", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], "testuser")
        self.assertFalse(response.json()["is_admin"])
        self.assertNotIn("password", response.json())
        with Session(self.engine) as db:
            user = db.scalar(select(User))
            self.assertNotEqual(user.password, self.account["password"])
            self.assertTrue(verify_password(self.account["password"], user.password))

    def test_duplicate_and_invalid_registration(self):
        self.client.post("/register", json=self.account)
        self.assertEqual(self.client.post("/register", json=self.account).status_code, 409)
        invalid = {**self.account, "password": "short"}
        self.assertEqual(self.client.post("/register", json=invalid).status_code, 422)

    def test_invalid_login_and_tokens(self):
        self.register_and_login()
        for username in ("testuser", "missing", "' OR 1=1 --"):
            response = self.client.post("/login", json={
                "username": username, "password": "wrong-password",
            })
            self.assertEqual(response.status_code, 401)
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            self.assertEqual(self.client.get("/me", headers=headers).status_code, 401)
            self.assertEqual(self.client.get("/api/admin/check", headers=headers).status_code, 401)

    def test_admin_permission_comes_from_database(self):
        headers = self.register_and_login()
        self.assertEqual(self.client.get("/api/admin/check", headers=headers).status_code, 403)
        with Session(self.engine) as db:
            user = db.scalar(select(User))
            user.is_admin = True
            db.commit()
        response = self.client.get("/api/admin/check", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"admin": True})

    def test_registration_cannot_grant_admin(self):
        response = self.client.post("/register", json={**self.account, "is_admin": True})
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.json()["is_admin"])

    def test_legacy_password_is_rejected_without_server_error(self):
        with Session(self.engine) as db:
            db.add(User(username="legacy", email="legacy@example.com", password="old-demo-value"))
            db.commit()
        response = self.client.post("/login", json={
            "username": "legacy", "password": "old-demo-value",
        })
        self.assertEqual(response.status_code, 401)

    def test_pages_and_api_docs_are_served(self):
        for path in ("/", "/register", "/user", "/admin", "/docs"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn("text/html", response.headers["content-type"])

    def test_user_list_requires_admin_and_excludes_passwords(self):
        headers = self.register_and_login()
        self.assertEqual(self.client.get("/api/admin/users").status_code, 401)
        self.assertEqual(self.client.get("/api/admin/users", headers=headers).status_code, 403)
        with Session(self.engine) as db:
            db.scalar(select(User)).is_admin = True
            db.commit()
        response = self.client.get("/api/admin/users", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["username"], "testuser")
        self.assertNotIn("password", response.json()[0])


if __name__ == "__main__":
    unittest.main()
