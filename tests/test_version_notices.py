import asyncio
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock
from urllib.parse import urlparse

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fy_auth import AuthService, AuthSettings, auth_middleware  # noqa: E402


def settings():
    return AuthSettings(
        app_id="",
        app_secret="",
        redirect_uri="",
        redirect_uris=[],
        session_secret="test-secret",
        super_admin_ids=[],
        bitable_app_token="",
        members_table_id="",
        roles_table_id="",
        cookie_secure=False,
        default_role="member",
    )


def request(path, method="GET"):
    parsed = urlparse(path)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": parsed.path,
        "raw_path": parsed.path.encode("ascii"),
        "query_string": parsed.query.encode("ascii"),
        "headers": [(b"host", b"127.0.0.1:3000")],
        "client": ("127.0.0.1", 1234),
        "server": ("127.0.0.1", 3000),
    }
    return Request(scope)


class VersionNoticeContractTests(unittest.TestCase):
    def test_fy_notes_match_current_fy_version(self):
        with open(os.path.join(ROOT, "FY_VERSION"), encoding="utf-8") as handle:
            version = handle.read().strip()
        with open(os.path.join(ROOT, "static", "fy-update-notes.json"), encoding="utf-8") as handle:
            notes = json.load(handle)
        self.assertEqual(notes["version"], version)
        self.assertGreater(len(notes["items"]), 0)
        self.assertLessEqual(len(notes["items"]), 3)
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

    def test_member_ui_has_read_only_fy_version_path(self):
        with open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("appInfo.fy_version", source)
        self.assertIn("appInfo.fy_update_notes", source)
        self.assertIn("projectUpdateReadOnly", source)
        self.assertIn("if(!isProjectUpdateAdmin())", source)
        self.assertNotIn("FY 定制版", source)
        self.assertNotIn("FY Edition", source)


class VersionUpdateMiddlewareTests(unittest.TestCase):
    UPDATE_PATHS = (
        "/api/check-update",
        "/api/update-connectivity",
        "/api/update-connectivity/probe?name=Google%20%E8%BF%9E%E9%80%9A%E6%80%A7",
        "/api/update-backups",
        "/api/update-from-github",
        "/api/update-rollback",
    )

    def run_request(self, user, path, method="GET"):
        service = AuthService(settings())
        service.current_user = AsyncMock(return_value=user)
        next_handler = AsyncMock(return_value=JSONResponse({"ok": True}))
        response = asyncio.run(auth_middleware(service, request(path, method), next_handler))
        return response, next_handler

    def test_member_cannot_read_or_execute_update_apis(self):
        user = {"is_super_admin": False, "read_only": False, "permissions": ["settings:more:manage"]}
        for path in self.UPDATE_PATHS:
            method = "POST" if path in ("/api/update-from-github", "/api/update-rollback") else "GET"
            response, next_handler = self.run_request(user, path, method)
            self.assertEqual(response.status_code, 403, path)
            next_handler.assert_not_awaited()

    def test_super_admin_can_reach_update_apis(self):
        user = {"is_super_admin": True, "read_only": False, "permissions": []}
        for path in self.UPDATE_PATHS:
            method = "POST" if path in ("/api/update-from-github", "/api/update-rollback") else "GET"
            response, next_handler = self.run_request(user, path, method)
            self.assertEqual(response.status_code, 200, path)
            next_handler.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
