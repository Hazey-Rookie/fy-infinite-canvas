import asyncio
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fy_auth import (  # noqa: E402
    OAUTH_STATE_COOKIE,
    AuthService,
    AuthSettings,
    DEFAULT_ROLES,
    FeishuAPIError,
    SignedTokenCodec,
    TENANT_NAME_SYNC_INTERVAL_SECONDS,
    _management_permission,
    auth_middleware,
    register_auth,
)


LOCAL_CALLBACK = "http://127.0.0.1:8000/auth/callback"
ONLINE_CALLBACK = "http://canvas.example.com:808/auth/callback"


def settings(**overrides):
    values = {
        "app_id": "",
        "app_secret": "",
        "redirect_uri": "",
        "redirect_uris": [],
        "session_secret": "test-secret",
        "super_admin_ids": [],
        "cookie_secure": False,
        "default_role": "member",
    }
    values.update(overrides)
    return AuthSettings(**values)


def endpoint(app, path, method="GET"):
    return next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", "") == path and method in getattr(route, "methods", set())
    )


class SignedTokenCodecTests(unittest.TestCase):
    def test_round_trip_and_tamper_rejection(self):
        codec = SignedTokenCodec("secret")
        token = codec.encode({"kind": "session", "user": {"open_id": "ou_1"}}, 60)
        self.assertEqual(codec.decode(token)["user"]["open_id"], "ou_1")
        self.assertIsNone(codec.decode(token + "broken"))

    def test_expired_token_is_rejected(self):
        codec = SignedTokenCodec("secret")
        with patch("fy_auth.time.time", return_value=100):
            token = codec.encode({"kind": "session"}, 1)
        with patch("fy_auth.time.time", return_value=102):
            self.assertIsNone(codec.decode(token))


class LocalAccountTenantTests(unittest.TestCase):
    def test_same_username_isolated_by_tenant(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuthService(settings(
                db_path=":memory:",
                tenants={
                    "alpha": {"tenant_key": "alpha", "name": "Alpha", "app_id": "a", "app_secret": "s", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                    "beta": {"tenant_key": "beta", "name": "Beta", "app_id": "b", "app_secret": "t", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                },
            ))
            alpha = service.local_accounts.create("partner", "Alpha partner", "strong-pass", "guest", "alpha")
            beta = service.local_accounts.create("partner", "Beta partner", "strong-pass", "member", "beta")
            self.assertEqual(alpha["tenant_key"], "alpha")
            self.assertEqual(beta["tenant_key"], "beta")
            self.assertEqual(service.local_accounts.authenticate("partner", "strong-pass", "alpha")["tenant_key"], "alpha")
            self.assertEqual(service.local_accounts.authenticate("partner", "strong-pass", "beta")["role"], "member")
            self.assertIsNone(service.local_accounts.authenticate("partner", "wrong", "alpha"))

    def test_create_endpoint_requires_target_tenant_role(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AuthService(settings(
                db_path=":memory:",
                super_admin_ids=["ou_admin"],
                tenants={
                    "alpha": {"tenant_key": "alpha", "name": "Alpha", "app_id": "a", "app_secret": "s", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                    "beta": {"tenant_key": "beta", "name": "Beta", "app_id": "b", "app_secret": "t", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                },
            ))
            service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "tenant_key": "alpha", "is_super_admin": True})
            app = FastAPI()
            register_auth(app, service)
            create = endpoint(app, "/api/admin/local-accounts", "POST")
            account = asyncio.run(create(MiddlewareBoundaryTests.request(), {"tenant_key": "beta", "username": "partner", "display_name": "外部", "password": "strong-pass", "role": "member"}))
            self.assertEqual(account["tenant_key"], "beta")
            self.assertEqual(account["role"], "member")
            with self.assertRaises(HTTPException) as duplicate:
                asyncio.run(create(MiddlewareBoundaryTests.request(), {"tenant_key": "beta", "username": "Partner", "display_name": "重复账号", "password": "strong-pass", "role": "guest"}))
            self.assertEqual(duplicate.exception.status_code, 409)
            with self.assertRaises(HTTPException) as error:
                asyncio.run(create(MiddlewareBoundaryTests.request(), {"tenant_key": "beta", "username": "bad", "display_name": "外部", "password": "strong-pass", "role": "missing"}))
            self.assertEqual(error.exception.status_code, 400)

    def test_update_endpoint_persists_role_status_and_expiry_within_tenant(self):
        service = AuthService(settings(
            db_path=":memory:",
            super_admin_ids=["ou_admin"],
            tenants={
                "alpha": {"tenant_key": "alpha", "name": "Alpha", "app_id": "a", "app_secret": "s", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                "beta": {"tenant_key": "beta", "name": "Beta", "app_id": "b", "app_secret": "t", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
            },
        ))
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "tenant_key": "alpha", "is_super_admin": True})
        account = service.local_accounts.create("partner", "Beta partner", "strong-pass", "member", "beta")
        app = FastAPI()
        register_auth(app, service)
        update = endpoint(app, "/api/admin/local-accounts/{account_id}", "PATCH")
        expires_at = time.time() + 14 * 24 * 60 * 60

        updated = asyncio.run(update(
            MiddlewareBoundaryTests.request(method="PATCH"),
            account["id"],
            {"role": "guest", "status": "disabled", "expires_at": expires_at},
            "beta",
        ))

        self.assertEqual(updated["tenant_key"], "beta")
        self.assertEqual(updated["role"], "guest")
        self.assertEqual(updated["status"], "disabled")
        self.assertAlmostEqual(updated["expires_at"], expires_at, places=3)
        persisted = service.local_accounts.get(account["id"], "beta")
        self.assertEqual(persisted["role"], "guest")
        self.assertEqual(persisted["status"], "disabled")
        self.assertAlmostEqual(persisted["expires_at"], expires_at, places=3)

        with self.assertRaises(HTTPException) as wrong_tenant:
            asyncio.run(update(
                MiddlewareBoundaryTests.request(method="PATCH"),
                account["id"],
                {"status": "active"},
                "alpha",
            ))
        self.assertEqual(wrong_tenant.exception.status_code, 404)


class RoleContractTests(unittest.TestCase):
    def test_member_and_guest_defaults(self):
        self.assertIn("action:read", DEFAULT_ROLES["admin"]["permissions"])
        self.assertIn("action:write", DEFAULT_ROLES["member"]["permissions"])
        self.assertNotIn("menu:api-settings", DEFAULT_ROLES["member"]["permissions"])
        self.assertIn("action:read", DEFAULT_ROLES["guest"]["permissions"])
        self.assertNotIn("action:write", DEFAULT_ROLES["guest"]["permissions"])

    def test_configured_identity_is_the_only_default_super_admin(self):
        service = AuthService(settings(super_admin_ids=["ou_super_admin"]))
        owner = asyncio.run(service.resolve_profile({"open_id": "ou_super_admin", "name": "默认超管"}))
        tenant_manager = asyncio.run(service.resolve_profile({
            "open_id": "ou_other_admin",
            "name": "其他企业管理员",
            "is_tenant_manager": True,
        }))
        self.assertEqual(owner["role"], "admin")
        self.assertTrue(owner["is_super_admin"])
        self.assertIn("organization:manage", owner["permissions"])
        self.assertEqual(tenant_manager["role"], "member")
        self.assertFalse(tenant_manager["is_super_admin"])

    def test_default_super_admin_cannot_be_disabled_by_member_record(self):
        service = AuthService(settings(
            super_admin_ids=["ou_super_admin"],
        ))
        service.store.member_for = AsyncMock(return_value={"role": "guest", "status": "disabled"})
        service.store.role_map = AsyncMock(return_value=DEFAULT_ROLES)
        profile = asyncio.run(service.resolve_profile({"open_id": "ou_super_admin"}))
        self.assertEqual(profile["role"], "admin")
        self.assertEqual(profile["status"], "active")
        self.assertFalse(profile["read_only"])

    def test_settings_mutations_have_explicit_permissions(self):
        self.assertEqual(_management_permission("/api/providers", "PUT"), "settings:api:manage")
        self.assertEqual(_management_permission("/api/storage-settings", "PATCH"), "settings:more:manage")
        self.assertEqual(_management_permission("/api/providers", "GET"), "")

    def test_studio_refreshes_changed_permissions_without_a_manual_reload(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"), "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("window.addEventListener('focus', refreshAccessProfile)", source)
        self.assertIn("document.addEventListener('visibilitychange'", source)
        self.assertIn("window.setInterval(refreshAccessProfile, 15000)", source)
        self.assertIn("user.is_tenant_admin ? '企业管理员'", source)
        settings_group_start = source.index('<div class="settings-fold-group')
        settings_group_end = source.index("</div>", settings_group_start)
        organization_menu = source.index('data-permission="menu:organization-permissions"')
        self.assertGreater(organization_menu, settings_group_end)

    def test_websocket_runtime_dependency_is_declared(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "requirements.txt"), "r", encoding="utf-8") as handle:
            dependencies = {line.strip().lower() for line in handle if line.strip() and not line.startswith("#")}
        self.assertIn("websockets", dependencies)


class FeishuSSOTests(unittest.TestCase):
    def configured_service(self):
        return AuthService(settings(
            app_id="cli_test",
            app_secret="secret",
            redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK, ONLINE_CALLBACK],
            super_admin_ids=["ou_super_admin"],
        ))

    def test_environment_supports_local_and_online_callbacks(self):
        with patch.dict(os.environ, {
            "FEISHU_APP_ID": "cli_test",
            "FEISHU_APP_SECRET": "secret",
            "FEISHU_REDIRECT_URIS": f"{LOCAL_CALLBACK},{ONLINE_CALLBACK}",
            "FY_SUPER_ADMIN_IDS": "ou_super_admin",
        }, clear=True):
            configured = AuthSettings.from_env()
        self.assertEqual(configured.allowed_redirect_uris, [LOCAL_CALLBACK, ONLINE_CALLBACK])
        self.assertTrue(configured.sso_configured)
        self.assertEqual(configured.default_role, "member")

    def test_sso_requires_default_super_admin_identity(self):
        configured = settings(
            app_id="cli_test",
            app_secret="secret",
            redirect_uri=LOCAL_CALLBACK,
        )
        self.assertFalse(configured.sso_configured)
        self.assertIn("FY_SUPER_ADMIN_IDS", configured.missing_sso_fields())

    def test_authorize_url_uses_supplied_callback(self):
        service = self.configured_service()
        url = urlparse(service.feishu.authorize_url("signed-state", ONLINE_CALLBACK))
        query = parse_qs(url.query)
        self.assertEqual(query["app_id"], ["cli_test"])
        self.assertEqual(query["redirect_uri"], [ONLINE_CALLBACK])
        self.assertEqual(query["state"], ["signed-state"])

    def test_exchange_code_uses_same_callback_and_normalizes_user(self):
        service = self.configured_service()
        service.feishu._request = AsyncMock(return_value={
            "code": 0,
            "data": {"user_info": {"open_id": "ou_123", "name": "测试用户"}},
        })
        user = asyncio.run(service.feishu.exchange_code("auth-code", ONLINE_CALLBACK))
        self.assertEqual(user["open_id"], "ou_123")
        request = service.feishu._request.await_args
        self.assertEqual(request.kwargs["json"]["redirect_uri"], ONLINE_CALLBACK)

    def test_exchange_code_fetches_user_info_for_v2_token_response(self):
        service = self.configured_service()
        service.feishu._request = AsyncMock(side_effect=[
            {"code": 0, "data": {"access_token": "u-token", "token_type": "Bearer"}},
            {"code": 0, "data": {"open_id": "ou_123", "name": "测试用户"}},
        ])

        user = asyncio.run(service.feishu.exchange_code("auth-code", LOCAL_CALLBACK))

        self.assertEqual(user["open_id"], "ou_123")
        self.assertEqual(service.feishu._request.await_count, 2)
        profile_request = service.feishu._request.await_args_list[1]
        self.assertEqual(profile_request.args[0], "GET")
        self.assertTrue(profile_request.args[1].endswith("/authen/v1/user_info"))
        self.assertEqual(profile_request.kwargs["headers"], {"Authorization": "Bearer u-token"})

    def test_tenant_info_uses_feishu_query_endpoint(self):
        service = self.configured_service()
        service.feishu.tenant_headers = AsyncMock(return_value={"Authorization": "Bearer tenant-token"})
        service.feishu._request = AsyncMock(return_value={
            "code": 0,
            "data": {"tenant": {"name": "飞书实际企业名称"}},
        })

        result = asyncio.run(service.feishu.get_tenant_info())

        self.assertEqual(result["name"], "飞书实际企业名称")
        request = service.feishu._request.await_args
        self.assertEqual(request.args[0], "GET")
        self.assertTrue(request.args[1].endswith("/tenant/v2/tenant/query"))

    def test_login_selects_callback_matching_request_origin(self):
        service = self.configured_service()
        app = FastAPI()
        register_auth(app, service)
        login = endpoint(app, "/api/auth/feishu/login")
        for host, expected in (("127.0.0.1:8000", LOCAL_CALLBACK), ("canvas.example.com:808", ONLINE_CALLBACK)):
            response = asyncio.run(login(MiddlewareBoundaryTests.request(
                method="GET", path="/api/auth/feishu/login", host=host
            ), "/static/canvas.html"))
            query = parse_qs(urlparse(response.headers["location"]).query)
            self.assertEqual(query["redirect_uri"], [expected])
            state_payload = service.codec.decode(query["state"][0])
            self.assertEqual(state_payload["redirect_uri"], expected)

    def test_login_returns_to_original_local_port_after_cross_port_callback(self):
        callback = "http://127.0.0.1:3000/auth/callback"
        service = AuthService(settings(
            app_id="cli_test",
            app_secret="secret",
            redirect_uri=callback,
            redirect_uris=[callback],
            super_admin_ids=["ou_super_admin"],
            db_path=":memory:",
        ))
        service.feishu.exchange_code = AsyncMock(return_value={"open_id": "ou_new", "name": "新成员"})
        service.feishu.get_user = AsyncMock(return_value={"open_id": "ou_new", "name": "新成员"})
        app = FastAPI()
        register_auth(app, service)

        login = endpoint(app, "/api/auth/feishu/login")
        login_response = asyncio.run(login(MiddlewareBoundaryTests.request(
            method="GET", path="/api/auth/feishu/login", host="127.0.0.1:8000"
        ), "/"))
        login_query = parse_qs(urlparse(login_response.headers["location"]).query)
        state = login_query["state"][0]
        state_payload = service.codec.decode(state)
        self.assertEqual(login_query["redirect_uri"], [callback])
        self.assertEqual(state_payload["return_origin"], "http://127.0.0.1:8000")

        callback_endpoint = endpoint(app, "/auth/callback")
        callback_request = MiddlewareBoundaryTests.request(
            method="GET", path="/auth/callback", host="127.0.0.1:3000",
            cookies={OAUTH_STATE_COOKIE: state},
        )
        callback_response = asyncio.run(callback_endpoint(callback_request, "auth-code", state))

        self.assertEqual(callback_response.headers["location"], "http://127.0.0.1:8000/")

    def test_callback_creates_session_without_adding_member_record(self):
        service = AuthService(settings(
            app_id="cli_test",
            app_secret="secret",
            redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK],
            super_admin_ids=["ou_super_admin"],
        ))
        service.feishu.exchange_code = AsyncMock(return_value={"open_id": "ou_new", "name": "新成员", "tenant_key": "tenant_external_id"})
        service.feishu.get_user = AsyncMock(return_value={"open_id": "ou_new", "name": "新成员", "tenant_key": "tenant_external_id"})
        service.store.save_member = AsyncMock()
        state = service.codec.encode({
            "kind": "oauth", "nonce": "nonce", "return_to": "/", "redirect_uri": LOCAL_CALLBACK,
        }, 600)
        app = FastAPI()
        register_auth(app, service)
        callback = endpoint(app, "/auth/callback")
        request = MiddlewareBoundaryTests.request(
            method="GET", path="/auth/callback", cookies={OAUTH_STATE_COOKIE: state}
        )
        response = asyncio.run(callback(request, "auth-code", state))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/")
        service.feishu.exchange_code.assert_awaited_once_with("auth-code", LOCAL_CALLBACK)
        service.store.save_member.assert_not_awaited()
        self.assertIn("fy_session=", response.headers.get("set-cookie", ""))

    def test_callback_uses_oauth_identity_when_contact_lookup_is_forbidden(self):
        service = self.configured_service()
        service.feishu.exchange_code = AsyncMock(return_value={"open_id": "ou_new", "name": "新成员"})
        service.feishu.get_user = AsyncMock(side_effect=FeishuAPIError("no dept authority error"))
        state = service.codec.encode({
            "kind": "oauth", "nonce": "nonce", "return_to": "/", "redirect_uri": LOCAL_CALLBACK,
        }, 600)
        app = FastAPI()
        register_auth(app, service)
        callback = endpoint(app, "/auth/callback")
        request = MiddlewareBoundaryTests.request(
            method="GET", path="/auth/callback", cookies={OAUTH_STATE_COOKIE: state}
        )

        response = asyncio.run(callback(request, "auth-code", state))

        self.assertEqual(response.status_code, 302)
        self.assertIn("fy_session=", response.headers.get("set-cookie", ""))
        service.feishu.get_user.assert_awaited_once_with({"open_id": "ou_new", "name": "新成员"})

    def test_callback_rejects_callback_not_in_allowlist(self):
        service = self.configured_service()
        state = service.codec.encode({
            "kind": "oauth", "nonce": "nonce", "return_to": "/",
            "redirect_uri": "https://evil.example/auth/callback",
        }, 600)
        app = FastAPI()
        register_auth(app, service)
        callback = endpoint(app, "/auth/callback")
        request = MiddlewareBoundaryTests.request(
            method="GET", path="/auth/callback", cookies={OAUTH_STATE_COOKIE: state}
        )
        with self.assertRaises(HTTPException) as error:
            asyncio.run(callback(request, "auth-code", state))
        self.assertEqual(error.exception.status_code, 400)

    def test_public_config_reports_missing_external_values(self):
        config = AuthService(settings()).public_config()
        self.assertTrue(config["sso_enabled"])
        self.assertFalse(config["sso_configured"])
        self.assertEqual(config["permission_store"], "local")
        self.assertNotIn("bitable_enabled", config)
        self.assertIn("FEISHU_APP_ID", config["missing_sso_fields"])
        self.assertIn("FY_SUPER_ADMIN_IDS", config["missing_sso_fields"])

    def test_missing_credentials_never_fall_back_to_local_user(self):
        service = AuthService(settings())
        self.assertIsNone(asyncio.run(service.current_user(MiddlewareBoundaryTests.request(method="GET", path="/"))))
        app = FastAPI()
        register_auth(app, service)
        login = endpoint(app, "/api/auth/feishu/login")
        with self.assertRaises(HTTPException) as error:
            asyncio.run(login(MiddlewareBoundaryTests.request(method="GET", path="/api/auth/feishu/login"), "/"))
        self.assertEqual(error.exception.status_code, 503)


class LoginPageTenantSelectionTests(unittest.TestCase):
    def test_feishu_login_stays_disabled_until_a_tenant_is_selected(self):
        path = os.path.join(os.path.dirname(__file__), "..", "static", "login.html")
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn('id="loginMethods"', source)
        self.assertIn('id="feishuTab"', source)
        self.assertIn('id="localTab"', source)
        self.assertIn('id="feishuPanel"', source)
        self.assertIn('id="localPanel"', source)
        self.assertIn('id="feishuTab" class="method-tab" type="button" role="tab" aria-selected="true"', source)
        self.assertIn('<button id="loginBtn" type="button" disabled>使用飞书登录</button>', source)
        self.assertIn("let selectedTenant = '';", source)
        self.assertIn("loginButton.disabled = false;", source)
        self.assertIn("if(!selectedTenant) return;", source)
        self.assertIn("localTab.addEventListener('click', () => setMode('local'));", source)
        self.assertNotIn('href="/api/auth/feishu/login?return_to=%2F"', source)

    def test_local_login_requires_a_tenant_option(self):
        path = os.path.join(os.path.dirname(__file__), "..", "static", "login.html")
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()

        self.assertIn('<select id="localTenant" aria-label="选择企业" required>', source)
        self.assertIn('<option value="" selected disabled>请选择企业</option>', source)
        self.assertIn('placeholder="账号"', source)


class OrganizationTests(unittest.TestCase):
    def test_tenant_name_sync_interval_is_five_minutes(self):
        self.assertEqual(TENANT_NAME_SYNC_INTERVAL_SECONDS, 300)

    def test_organization_ui_exposes_separate_profile_and_member_sync_actions(self):
        html_path = os.path.join(os.path.dirname(__file__), "..", "static", "org-permissions.html")
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "org-permissions.js")
        with open(html_path, "r", encoding="utf-8") as handle:
            html_source = handle.read()
        with open(js_path, "r", encoding="utf-8") as handle:
            js_source = handle.read()

        self.assertIn('id="syncTenantProfileBtn"', html_source)
        self.assertIn('id="syncTenantBtn"', html_source)
        self.assertIn('/sync-profile`,{method:\'POST\'}', js_source)
        self.assertIn('/sync`,{method:\'POST\'}', js_source)
        self.assertIn('Promise.all([', js_source)
        self.assertNotIn('refresh=true', js_source)

    def test_organization_syncs_root_users_and_marks_managed_assignments(self):
        service = AuthService(settings(super_admin_ids=["ou_super_admin"]))
        service.store.set_tenant_enabled("tenant_fy", True, "测试企业")
        service.feishu.list_departments = AsyncMock(return_value=[
            {"open_department_id": "od_sales", "name": "销售部"},
        ])
        service.feishu.get_root_department = AsyncMock(return_value={"open_department_id": "0", "name": "测试企业"})

        async def users_for(department_id):
            if department_id == "0":
                return [{"open_id": "ou_super_admin", "name": "默认超管", "department_ids": []}]
            return [{"open_id": "ou_sales", "name": "销售", "department_ids": ["od_sales"]}]

        service.feishu.list_users_for_department = AsyncMock(side_effect=users_for)
        service.store.snapshot = AsyncMock(return_value={
            "members": [{"record_id": "rec_1", "open_id": "ou_sales", "role": "guest", "status": "active"}],
            "roles": DEFAULT_ROLES,
            "source": "local",
        })
        current_user = {"open_id": "ou_super_admin", "tenant_key": "tenant_fy", "is_super_admin": True}
        result = asyncio.run(service.organization(current_user=current_user, refresh=True))
        users = {user["open_id"]: user for user in result["users"]}
        self.assertEqual(users["ou_super_admin"]["role"], "admin")
        self.assertFalse(users["ou_super_admin"]["managed"])
        self.assertEqual(users["ou_sales"]["role"], "guest")
        self.assertTrue(users["ou_sales"]["managed"])
        self.assertEqual(result["tenant_key"], "tenant_fy")
        self.assertEqual(result["tenant"]["name"], "测试企业")
        called_ids = [call.args[0] for call in service.feishu.list_users_for_department.await_args_list]
        self.assertEqual(set(called_ids), {"0", "od_sales"})
        asyncio.run(service.organization(current_user=current_user))
        self.assertEqual(service.feishu.list_departments.await_count, 1)

    def test_organization_infers_department_membership_from_department_queries(self):
        service = AuthService(settings())
        service.feishu.list_departments = AsyncMock(return_value=[
            {"open_department_id": "od_sales", "name": "销售部"},
            {"open_department_id": "od_design", "name": "设计部"},
        ])
        service.feishu.get_root_department = AsyncMock(return_value={"open_department_id": "0", "name": "测试企业"})

        async def users_for(department_id):
            if department_id == "0":
                return []
            return [{"open_id": "ou_shared", "name": "跨部门成员"}]

        service.feishu.list_users_for_department = AsyncMock(side_effect=users_for)
        service.store.snapshot = AsyncMock(return_value={
            "members": [], "roles": DEFAULT_ROLES, "source": "local",
        })
        result = asyncio.run(service.organization(refresh=True))
        self.assertEqual(len(result["users"]), 1)
        self.assertEqual(
            result["users"][0]["department_ids"],
            ["od_sales", "od_design"],
        )

    def test_auth_me_reports_tenant_and_department_names(self):
        service = AuthService(settings(
            db_path=":memory:",
            tenants={
                "default": {
                    "tenant_key": "default", "name": "示例企业", "app_id": "", "app_secret": "",
                    "redirect_uris": [], "enabled": True,
                },
            },
        ))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_user", "name": "示例用户", "tenant_key": "default",
            "department_ids": ["od_product"], "role": "member", "permissions": [],
            "is_super_admin": False, "is_tenant_admin": False,
        })
        asyncio.run(service.store.sync_directory([], "default", departments=[
            {"open_department_id": "od_product", "name": "产品部"},
        ]))
        service.feishu.list_departments = AsyncMock(side_effect=AssertionError("auth/me must not query Feishu"))
        app = FastAPI()
        register_auth(app, service)
        auth_me = endpoint(app, "/api/auth/me")
        result = asyncio.run(auth_me(MiddlewareBoundaryTests.request(method="GET", path="/api/auth/me")))
        self.assertEqual(result["tenant"]["name"], "示例企业")
        self.assertEqual(result["user"]["department_names"], ["产品部"])
        self.assertEqual(result["config"]["permission_store"], "local")
        service.feishu.list_departments.assert_not_awaited()

    def test_organization_initial_load_reads_sqlite_without_feishu_requests(self):
        service = AuthService(settings(db_path=":memory:"))
        asyncio.run(service.store.sync_directory(
            [{"open_id": "ou_local", "name": "本地成员", "department_ids": ["od_product"]}],
            "default",
            departments=[{"open_department_id": "od_product", "name": "产品部"}],
        ))
        service.feishu.get_root_department = AsyncMock(side_effect=AssertionError("initial load must stay local"))
        service.feishu.list_departments = AsyncMock(side_effect=AssertionError("initial load must stay local"))
        service.feishu.list_users_for_department = AsyncMock(side_effect=AssertionError("initial load must stay local"))

        result = asyncio.run(service.organization(current_user={"open_id": "ou_local", "tenant_key": "default"}))

        self.assertEqual(result["departments"][0]["name"], "产品部")
        self.assertEqual(result["users"][0]["name"], "本地成员")
        service.feishu.get_root_department.assert_not_awaited()
        service.feishu.list_departments.assert_not_awaited()
        service.feishu.list_users_for_department.assert_not_awaited()

    def test_tenant_summary_does_not_expose_internal_identifier_as_name(self):
        service = AuthService(settings(db_path=":memory:"))
        opaque_key = "abcdef0123456789"
        summary = service.tenant_summary(opaque_key)
        self.assertEqual(summary["name"], "当前企业")

    def test_tenant_list_ignores_orphaned_database_tenants(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={"default": {"tenant_key": "default", "name": "默认企业", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True}},
        ))
        service.store.set_tenant_enabled("orphaned", True, "orphaned")
        self.assertEqual([item["tenant_key"] for item in service.list_tenants()], ["default"])

    def test_default_tenant_summary_uses_friendly_fallback_name(self):
        service = AuthService(settings(db_path=":memory:"))
        self.assertEqual(service.tenant_summary("default")["name"], "默认企业")

    def test_default_tenant_display_name_refreshes_from_feishu_tenant_info(self):
        service = AuthService(settings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], db_path=":memory:",
        ))
        service.feishu.get_tenant_info = AsyncMock(return_value={"name": "扶摇Studio"})
        service.feishu.get_root_department = AsyncMock(side_effect=AssertionError("tenant info should be preferred"))

        summary = asyncio.run(service.sync_tenant_profile("default"))

        self.assertEqual(summary["name"], "扶摇Studio")
        self.assertEqual(service.list_tenants()[0]["name"], "扶摇Studio")

    def test_feishu_tenant_name_replaces_a_stale_custom_name(self):
        service = AuthService(settings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], db_path=":memory:",
        ))
        service.store.set_tenant_enabled("default", True, "扶摇企业")
        service.feishu.get_tenant_info = AsyncMock(return_value={"name": "飞书实际企业名称"})
        service.feishu.get_root_department = AsyncMock(side_effect=AssertionError("tenant info should be preferred"))

        summary = asyncio.run(service.sync_tenant_profile("default"))

        self.assertEqual(summary["name"], "飞书实际企业名称")
        self.assertEqual(service.list_tenants()[0]["name"], "飞书实际企业名称")

    def test_platform_tenant_list_reads_names_from_database(self):
        service = AuthService(settings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], db_path=":memory:", super_admin_ids=["ou_admin"],
        ))
        service.store.set_tenant_enabled("default", True, "扶摇企业")
        service.feishu.get_tenant_info = AsyncMock(return_value={"name": "飞书实际企业名称"})
        service.feishu.get_root_department = AsyncMock(side_effect=AssertionError("tenant info should be preferred"))
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "is_super_admin": True})
        app = FastAPI()
        register_auth(app, service)

        list_tenants = endpoint(app, "/api/admin/tenants")
        result = asyncio.run(list_tenants(MiddlewareBoundaryTests.request()))

        self.assertEqual(result["tenants"][0]["name"], "扶摇企业")
        service.feishu.get_tenant_info.assert_not_awaited()

    def test_public_auth_config_reads_tenant_names_from_database(self):
        service = AuthService(settings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], db_path=":memory:",
        ))
        service.store.set_tenant_enabled("default", True, "数据库企业名称")
        service.feishu.get_tenant_info = AsyncMock(return_value={"name": "飞书即时名称"})
        app = FastAPI()
        register_auth(app, service)

        auth_config = endpoint(app, "/api/auth/config")
        result = asyncio.run(auth_config())

        self.assertEqual(result["tenants"][0]["name"], "数据库企业名称")
        service.feishu.get_tenant_info.assert_not_awaited()

    def test_platform_admin_can_add_and_remove_tenants_but_not_last(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={"default": {"tenant_key": "default", "name": "默认企业", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True}},
        ))
        with patch("fy_auth._persist_tenant_configs") as persist:
            created = service.save_tenant({
                "tenant_key": "second", "name": "第二企业", "app_id": "cli_second",
                "app_secret": "secret_second", "redirect_uris": [LOCAL_CALLBACK],
            })
            self.assertEqual(created["name"], "第二企业")
            self.assertTrue(created["credential_configured"])
            self.assertTrue(persist.called)
            self.assertTrue(service.remove_tenant("second"))
            with self.assertRaises(FeishuAPIError):
                service.remove_tenant("default")

    def test_platform_admin_can_sync_selected_tenant(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={
                "default": {"tenant_key": "default", "name": "默认企业", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                "second": {"tenant_key": "second", "name": "第二企业", "app_id": "cli_second", "app_secret": "secret_second", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
            },
        ))
        client = service.feishu_for("second")
        client.get_tenant_info = AsyncMock(side_effect=AssertionError("member sync must not query tenant profile"))
        client.get_root_department = AsyncMock(return_value={"open_department_id": "0", "name": "第二企业"})
        client.list_departments = AsyncMock(return_value=[{"open_department_id": "od_sales", "name": "销售部"}])
        client.list_users_for_department = AsyncMock(return_value=[{"open_id": "ou_second", "name": "第二企业成员"}])
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "tenant_key": "default", "is_super_admin": True})
        app = FastAPI()
        register_auth(app, service)
        sync = endpoint(app, "/api/admin/tenants/{tenant_key}/sync", "POST")
        result = asyncio.run(sync(MiddlewareBoundaryTests.request(method="POST", path="/api/admin/tenants/second/sync"), "second"))
        self.assertEqual(result["tenant_key"], "second")
        self.assertEqual(result["members"], 1)
        self.assertEqual(service.tenant_summary("second")["name"], "第二企业")
        client.get_tenant_info.assert_not_awaited()
        member = asyncio.run(service.store.member_for({"open_id": "ou_second"}, "second"))
        self.assertEqual(member["name"], "第二企业成员")

    def test_platform_admin_can_sync_tenant_profile_independently(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={
                "default": {"tenant_key": "default", "name": "旧企业名称", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
            },
        ))
        service.feishu.get_tenant_info = AsyncMock(return_value={"name": "飞书企业名称"})
        service.feishu.get_root_department = AsyncMock(side_effect=AssertionError("profile sync must not query contacts"))
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "tenant_key": "default", "is_super_admin": True})
        service._tenant_name_expires_at["default"] = time.time() + 300
        app = FastAPI()
        register_auth(app, service)

        sync_profile = endpoint(app, "/api/admin/tenants/{tenant_key}/sync-profile", "POST")
        result = asyncio.run(sync_profile(
            MiddlewareBoundaryTests.request(method="POST", path="/api/admin/tenants/default/sync-profile"),
            "default",
        ))

        self.assertEqual(result["name"], "飞书企业名称")
        self.assertEqual(service.tenant_summary("default")["name"], "飞书企业名称")
        service.feishu.get_root_department.assert_not_awaited()

    def test_tenant_profile_sync_reports_its_own_permission_error(self):
        service = AuthService(settings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], db_path=":memory:", super_admin_ids=["ou_admin"],
        ))
        service.feishu.get_tenant_info = AsyncMock(side_effect=FeishuAPIError("缺少 tenant:tenant:readonly"))
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "is_super_admin": True})
        app = FastAPI()
        register_auth(app, service)
        sync_profile = endpoint(app, "/api/admin/tenants/{tenant_key}/sync-profile", "POST")

        with self.assertRaises(HTTPException) as error:
            asyncio.run(sync_profile(MiddlewareBoundaryTests.request(method="POST"), "default"))

        self.assertEqual(error.exception.status_code, 502)
        self.assertIn("tenant:tenant:readonly", error.exception.detail)

    def test_tenant_invitation_is_one_time_and_stores_only_hash(self):
        service = AuthService(settings(db_path=":memory:"))
        invitation = service.store.create_tenant_invitation("第二企业", 600)
        self.assertNotIn(invitation["token"], service.store._connect().execute("SELECT token_hash FROM tenant_invitations").fetchone()[0])
        self.assertTrue(service.store.claim_tenant_invitation(invitation["token"]))
        self.assertFalse(service.store.claim_tenant_invitation(invitation["token"]))
        service.store.finish_tenant_invitation(invitation["token"], True)
        self.assertTrue(service.store.tenant_invitation(invitation["token"])["used"])

    def test_platform_admin_invitation_acceptance_creates_verified_tenant(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={"default": {"tenant_key": "default", "name": "默认企业", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True}},
        ))
        service.current_user = AsyncMock(return_value={"open_id": "ou_admin", "tenant_key": "default", "is_super_admin": True})
        service.verify_tenant_connection = AsyncMock(return_value={"verified": True, "enterprise_name": "第二企业"})
        service.sync_tenant_profile = AsyncMock(return_value={"tenant_key": "second", "name": "第二企业"})
        service.sync_directory = AsyncMock(return_value={
            "tenant_key": "second", "departments": [{"name": "总办"}],
            "users": [{"open_id": "ou_member"}], "synced_at": 1,
        })
        app = FastAPI()
        register_auth(app, service)
        create = endpoint(app, "/api/admin/tenant-invitations", "POST")
        accept = endpoint(app, "/api/tenant-invitations/{token}/accept", "POST")
        with patch("fy_auth._persist_tenant_configs"):
            created = asyncio.run(create(MiddlewareBoundaryTests.request(method="POST", path="/api/admin/tenant-invitations"), {"tenant_name": "第二企业", "expires_in_minutes": 60}))
            token = created["invite_url"].split("token=", 1)[1]
            result = asyncio.run(accept(token, {"tenant_key": "second", "app_id": "cli_second", "app_secret": "secret_second", "redirect_uris": [LOCAL_CALLBACK]}))
        self.assertEqual(result["tenant"]["name"], "第二企业")
        self.assertEqual(result["initial_sync"], {"name": "第二企业", "departments": 1, "members": 1})
        self.assertEqual(result["login_url"], "/")
        self.assertTrue(service.tenant_exists("second"))
        service.sync_tenant_profile.assert_awaited_once_with("second", force=True, strict=True)
        service.sync_directory.assert_awaited_once_with("second")

    def test_tenant_onboarding_rolls_back_when_initial_member_sync_fails(self):
        service = AuthService(AuthSettings(
            app_id="cli_default", app_secret="secret_default", redirect_uri=LOCAL_CALLBACK,
            redirect_uris=[LOCAL_CALLBACK], session_secret="test-secret", super_admin_ids=["ou_admin"],
            cookie_secure=False, default_role="member", db_path=":memory:",
            tenants={"default": {"tenant_key": "default", "name": "默认企业", "app_id": "cli_default", "app_secret": "secret_default", "redirect_uris": [LOCAL_CALLBACK], "enabled": True}},
        ))
        service.verify_tenant_connection = AsyncMock(return_value={"verified": True, "enterprise_name": "第二企业"})
        service.sync_tenant_profile = AsyncMock(return_value={"tenant_key": "second", "name": "第二企业"})
        service.sync_directory = AsyncMock(side_effect=FeishuAPIError("缺少 contact:user.base:readonly"))
        invitation = service.store.create_tenant_invitation("第二企业", 600)
        app = FastAPI()
        register_auth(app, service)
        accept = endpoint(app, "/api/tenant-invitations/{token}/accept", "POST")

        with patch("fy_auth._persist_tenant_configs"):
            with self.assertRaises(HTTPException) as error:
                asyncio.run(accept(invitation["token"], {
                    "tenant_key": "second", "app_id": "cli_second", "app_secret": "secret_second",
                    "redirect_uris": [LOCAL_CALLBACK],
                }))

        self.assertEqual(error.exception.status_code, 502)
        self.assertIn("同步成员失败", error.exception.detail)
        self.assertIn("contact:user.base:readonly", error.exception.detail)
        self.assertFalse(service.tenant_exists("second"))
        self.assertFalse(service.store.tenant_invitation(invitation["token"])["used"])

    def test_resolve_profile_restores_department_ids_from_local_member(self):
        service = AuthService(settings(db_path=":memory:"))
        asyncio.run(service.store.save_member({
            "open_id": "ou_user", "name": "用户", "department_ids": ["od_product"],
        }))
        profile = asyncio.run(service.resolve_profile({"open_id": "ou_user", "tenant_key": "default"}))
        self.assertEqual(profile["department_ids"], ["od_product"])


class SQLitePermissionStoreTests(unittest.TestCase):
    def configured_service(self):
        return AuthService(settings(db_path=":memory:"))

    def test_snapshot_overlays_custom_roles_and_members(self):
        service = self.configured_service()
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "设计角色", "permissions": ["menu:canvas", "action:write"]}))
        asyncio.run(service.store.save_member({"open_id": "ou_designer", "name": "设计师", "role": "designer", "status": "active"}))
        snapshot = asyncio.run(service.store.snapshot(refresh=True))
        self.assertEqual(snapshot["members"][0]["role"], "designer")
        self.assertEqual(snapshot["roles"]["designer"]["display_name"], "设计角色")
        self.assertIn("admin", snapshot["roles"])

    def test_role_update_invalidates_cache_before_next_snapshot(self):
        service = self.configured_service()
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "设计角色", "permissions": ["action:read"]}))
        self.assertEqual(asyncio.run(service.store.snapshot())["roles"]["designer"]["permissions"], ["action:read"])
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "高级设计角色", "permissions": ["action:read", "action:write"]}))
        snapshot = asyncio.run(service.store.snapshot())
        self.assertEqual(snapshot["roles"]["designer"]["display_name"], "高级设计角色")
        self.assertEqual(snapshot["roles"]["designer"]["permissions"], ["action:read", "action:write"])

    def test_role_update_changes_member_profile_permissions_after_refresh(self):
        service = self.configured_service()
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "设计角色", "permissions": ["action:read"]}))
        asyncio.run(service.store.save_member({"open_id": "ou_designer", "name": "设计师", "role": "designer"}))
        before = asyncio.run(service.resolve_profile({"open_id": "ou_designer", "tenant_key": "default"}))
        self.assertNotIn("action:write", before["permissions"])
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "高级设计角色", "permissions": ["action:read", "action:write"]}))
        after = asyncio.run(service.resolve_profile({"open_id": "ou_designer", "tenant_key": "default"}))
        self.assertIn("action:write", after["permissions"])

    def test_member_upsert_reuses_existing_record(self):
        service = self.configured_service()
        asyncio.run(service.store.save_member({"open_id": "ou_1", "name": "成员", "role": "guest"}))
        updated = asyncio.run(service.store.save_member({"open_id": "ou_1", "name": "成员 2", "role": "guest"}))
        self.assertEqual(updated["name"], "成员 2")
        self.assertEqual(len(asyncio.run(service.store.snapshot())["members"]), 1)

    def test_delete_member_removes_local_override(self):
        service = self.configured_service()
        asyncio.run(service.store.save_member({"open_id": "ou_1", "name": "成员", "role": "guest", "status": "disabled"}))
        deleted = asyncio.run(service.store.delete_member({"open_id": "ou_1"}))
        self.assertTrue(deleted)
        member = asyncio.run(service.store.member_for({"open_id": "ou_1"}))
        self.assertEqual(member["role"], "")
        self.assertEqual(member["status"], "active")

    def test_members_are_isolated_by_tenant(self):
        service = AuthService(settings(
            db_path=":memory:",
            tenants={
                "alpha": {"tenant_key": "alpha", "name": "Alpha", "app_id": "a", "app_secret": "s", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                "beta": {"tenant_key": "beta", "name": "Beta", "app_id": "b", "app_secret": "t", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
            },
        ))
        asyncio.run(service.store.save_member({"open_id": "ou_same", "name": "Alpha user", "role": "guest"}, "alpha"))
        asyncio.run(service.store.save_member({"open_id": "ou_same", "name": "Beta user", "role": "admin"}, "beta"))
        self.assertEqual(asyncio.run(service.store.member_for({"open_id": "ou_same"}, "alpha"))["name"], "Alpha user")
        self.assertEqual(asyncio.run(service.store.member_for({"open_id": "ou_same"}, "beta"))["name"], "Beta user")

    def test_referenced_custom_role_cannot_be_deleted(self):
        service = self.configured_service()
        asyncio.run(service.store.save_role({"name": "designer", "display_name": "设计师", "permissions": ["action:read"]}))
        asyncio.run(service.store.save_member({"open_id": "ou_designer", "role": "designer"}))
        with self.assertRaises(FeishuAPIError):
            asyncio.run(service.store.delete_role("designer"))

    def test_admin_role_is_tenant_admin_and_receives_organization_permissions(self):
        service = self.configured_service()
        asyncio.run(service.store.save_member({"open_id": "ou_admin", "role": "admin"}))
        profile = asyncio.run(service.resolve_profile({"open_id": "ou_admin", "tenant_key": "default"}))
        self.assertTrue(profile["is_tenant_admin"])
        self.assertEqual(profile["role"], "admin")
        self.assertIn("action:read", profile["permissions"])
        self.assertIn("action:write", profile["permissions"])
        self.assertIn("menu:organization-permissions", profile["permissions"])
        self.assertIn("organization:manage", profile["permissions"])
        self.assertNotIn("roles:manage", profile["permissions"])
        self.assertNotIn("settings:api:manage", profile["permissions"])

    def test_legacy_tenant_admin_flag_does_not_elevate_a_non_admin_role(self):
        service = self.configured_service()
        asyncio.run(service.store.save_member({
            "open_id": "ou_member", "role": "member", "is_tenant_admin": True,
        }))
        profile = asyncio.run(service.resolve_profile({
            "open_id": "ou_member", "tenant_key": "default",
        }))
        self.assertFalse(profile["is_tenant_admin"])
        self.assertEqual(profile["role"], "member")
        self.assertNotIn("menu:organization-permissions", profile["permissions"])

    def test_admin_routes_save_only_to_local_store(self):
        service = AuthService(settings(db_path=":memory:", super_admin_ids=["ou_admin"]))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_admin", "tenant_key": "default", "is_super_admin": True,
        })
        service.feishu._request = AsyncMock(side_effect=AssertionError("authorization writes must not call Feishu"))
        app = FastAPI()
        register_auth(app, service)
        save_role = endpoint(app, "/api/admin/roles/{role_name}", "PUT")
        save_member = endpoint(app, "/api/admin/members/{open_id}", "PUT")
        role_request = MiddlewareBoundaryTests.request(method="PUT", path="/api/admin/roles/designer")
        member_request = MiddlewareBoundaryTests.request(method="PUT", path="/api/admin/members/ou_designer")
        role = asyncio.run(save_role(role_request, "designer", {
            "display_name": "设计师", "permissions": ["menu:canvas", "action:read"],
        }))
        member = asyncio.run(save_member(member_request, "ou_designer", {
            "name": "设计成员", "role": "designer", "status": "active",
        }))
        self.assertEqual(role["name"], "designer")
        self.assertEqual(member["role"], "designer")
        self.assertFalse(service.feishu._request.await_count)

    def test_tenant_admin_cannot_manage_roles(self):
        service = AuthService(settings(db_path=":memory:"))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_tenant_admin", "tenant_key": "default",
            "is_super_admin": False, "is_tenant_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        save_role = endpoint(app, "/api/admin/roles/{role_name}", "PUT")
        request = MiddlewareBoundaryTests.request(method="PUT", path="/api/admin/roles/local_admin")
        with self.assertRaises(HTTPException) as error:
            asyncio.run(save_role(request, "local_admin", {
                "display_name": "企业管理员角色",
                "permissions": ["action:read"],
            }))
        self.assertEqual(error.exception.status_code, 403)
        self.assertEqual(error.exception.detail, "只有平台超管可以管理角色")

    def test_tenant_admin_cannot_access_external_accounts(self):
        service = AuthService(settings(db_path=":memory:"))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_tenant_admin", "tenant_key": "default",
            "is_super_admin": False, "is_tenant_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        list_accounts = endpoint(app, "/api/admin/local-accounts", "GET")
        create_account = endpoint(app, "/api/admin/local-accounts", "POST")
        with self.assertRaises(HTTPException) as listed:
            asyncio.run(list_accounts(MiddlewareBoundaryTests.request(method="GET")))
        with self.assertRaises(HTTPException) as created:
            asyncio.run(create_account(MiddlewareBoundaryTests.request(), {
                "tenant_key": "default", "username": "partner", "display_name": "外部",
                "password": "strong-pass", "role": "member",
            }))
        self.assertEqual(listed.exception.status_code, 403)
        self.assertEqual(created.exception.status_code, 403)
        self.assertEqual(created.exception.detail, "只有平台超管可以管理外部账号")

    def test_tenant_admin_can_only_manage_members_in_own_tenant(self):
        service = AuthService(settings(
            db_path=":memory:",
            tenants={
                "alpha": {"tenant_key": "alpha", "name": "Alpha", "app_id": "a", "app_secret": "s", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
                "beta": {"tenant_key": "beta", "name": "Beta", "app_id": "b", "app_secret": "t", "redirect_uris": [LOCAL_CALLBACK], "enabled": True},
            },
        ))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_tenant_admin", "tenant_key": "alpha",
            "is_super_admin": False, "is_tenant_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        save_member = endpoint(app, "/api/admin/members/{open_id}", "PUT")
        member = asyncio.run(save_member(MiddlewareBoundaryTests.request(), "ou_alpha", {
            "name": "Alpha member", "role": "guest", "status": "active",
        }, "alpha"))
        self.assertEqual(member["role"], "guest")
        with self.assertRaises(HTTPException) as cross_tenant:
            asyncio.run(save_member(MiddlewareBoundaryTests.request(), "ou_beta", {
                "name": "Beta member", "role": "member", "status": "active",
            }, "beta"))
        self.assertEqual(cross_tenant.exception.status_code, 403)

    def test_tenant_admin_cannot_revoke_another_tenant_admin(self):
        service = AuthService(settings(db_path=":memory:"))
        asyncio.run(service.store.save_member({
            "open_id": "ou_other_admin", "role": "admin",
        }))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_tenant_admin", "tenant_key": "default",
            "is_super_admin": False, "is_tenant_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        delete_member = endpoint(app, "/api/admin/members/{open_id}", "DELETE")
        with self.assertRaises(HTTPException) as error:
            asyncio.run(delete_member(MiddlewareBoundaryTests.request(method="DELETE"), "ou_other_admin"))
        self.assertEqual(error.exception.status_code, 403)
        self.assertEqual(error.exception.detail, "只有平台超管可以授予或撤销管理员角色")

    def test_compatibility_tenant_admin_field_cannot_elevate_guest(self):
        service = AuthService(settings(db_path=":memory:", super_admin_ids=["ou_admin"]))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_admin", "tenant_key": "default", "is_super_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        save_member = endpoint(app, "/api/admin/members/{open_id}", "PUT")
        request = MiddlewareBoundaryTests.request(method="PUT", path="/api/admin/members/ou_guest")
        saved = asyncio.run(save_member(request, "ou_guest", {
            "name": "访客", "role": "guest", "status": "active", "is_tenant_admin": True,
        }))
        profile = asyncio.run(service.resolve_profile({
            "open_id": "ou_guest", "tenant_key": "default",
        }))
        self.assertEqual(saved["role"], "guest")
        self.assertFalse(saved["is_tenant_admin"])
        self.assertFalse(profile["is_tenant_admin"])

    def test_tenant_admin_cannot_grant_or_demote_admin_role(self):
        service = AuthService(settings(db_path=":memory:"))
        asyncio.run(service.store.save_member({"open_id": "ou_existing_admin", "role": "admin"}))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_tenant_admin", "tenant_key": "default",
            "is_super_admin": False, "is_tenant_admin": True,
        })
        app = FastAPI()
        register_auth(app, service)
        save_member = endpoint(app, "/api/admin/members/{open_id}", "PUT")
        request = MiddlewareBoundaryTests.request(method="PUT")
        for open_id, role in (("ou_member", "admin"), ("ou_existing_admin", "member")):
            with self.subTest(open_id=open_id, role=role), self.assertRaises(HTTPException) as error:
                asyncio.run(save_member(request, open_id, {"role": role, "status": "active"}))
            self.assertEqual(error.exception.status_code, 403)
            self.assertEqual(error.exception.detail, "只有平台超管可以授予或撤销管理员角色")

    def test_guest_member_record_does_not_resolve_as_tenant_admin(self):
        service = self.configured_service()
        asyncio.run(service.store.save_member({
            "open_id": "ou_legacy_guest", "role": "guest", "is_tenant_admin": True,
        }))
        profile = asyncio.run(service.resolve_profile({
            "open_id": "ou_legacy_guest", "tenant_key": "default",
        }))
        self.assertFalse(profile["is_tenant_admin"])
        self.assertNotIn("menu:organization-permissions", profile["permissions"])


class MiddlewareBoundaryTests(unittest.TestCase):
    @staticmethod
    def request(method="POST", path="/api/generate", host="127.0.0.1:8000", cookies=None):
        headers = [(b"host", host.encode("ascii"))]
        if cookies:
            value = "; ".join(f"{key}={item}" for key, item in cookies.items())
            headers.append((b"cookie", value.encode("ascii")))
        return Request({
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": tuple(host.rsplit(":", 1)),
        })

    def test_unauthenticated_api_is_rejected(self):
        service = AuthService(settings())
        next_handler = AsyncMock(return_value=JSONResponse({"ok": True}))
        response = asyncio.run(auth_middleware(service, self.request(), next_handler))
        self.assertEqual(response.status_code, 401)
        next_handler.assert_not_awaited()

    def test_guest_write_is_rejected_before_endpoint(self):
        service = AuthService(settings())
        service.current_user = AsyncMock(return_value={
            "role": "guest", "permissions": DEFAULT_ROLES["guest"]["permissions"],
            "read_only": True, "is_super_admin": False,
        })
        next_handler = AsyncMock(return_value=JSONResponse({"ok": True}))
        response = asyncio.run(auth_middleware(service, self.request(), next_handler))
        self.assertEqual(response.status_code, 403)
        next_handler.assert_not_awaited()

    def test_member_write_reaches_endpoint(self):
        service = AuthService(settings())
        service.current_user = AsyncMock(return_value={
            "role": "member", "permissions": DEFAULT_ROLES["member"]["permissions"],
            "read_only": False, "is_super_admin": False,
        })
        next_handler = AsyncMock(return_value=JSONResponse({"ok": True}))
        response = asyncio.run(auth_middleware(service, self.request(), next_handler))
        self.assertEqual(response.status_code, 200)
        next_handler.assert_awaited_once()

    def test_unauthenticated_static_html_redirects_to_login(self):
        service = AuthService(settings())
        next_handler = AsyncMock(return_value=JSONResponse({"ok": True}))
        response = asyncio.run(auth_middleware(
            service, self.request(method="GET", path="/static/canvas.html"), next_handler,
        ))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/static/login.html")

    def test_non_super_admin_cannot_manage_records(self):
        service = AuthService(settings())
        service.current_user = AsyncMock(return_value={
            "role": "custom-admin", "permissions": ["organization:manage", "roles:manage"],
            "is_super_admin": False,
        })
        service.store.save_member = AsyncMock()
        service.store.delete_member = AsyncMock()
        app = FastAPI()
        register_auth(app, service)
        request = self.request(method="PUT", path="/api/admin/members/ou_1")
        for method in ("PUT", "DELETE"):
            with self.assertRaises(HTTPException) as error:
                handler = endpoint(app, "/api/admin/members/{open_id}", method)
                if method == "PUT":
                    asyncio.run(handler(request, "ou_1", {"role": "admin"}))
                else:
                    asyncio.run(handler(request, "ou_1"))
            self.assertEqual(error.exception.status_code, 403)

    def test_default_super_admin_cannot_be_downgraded_or_deleted(self):
        service = AuthService(settings(super_admin_ids=["super_admin_user_id"]))
        service.current_user = AsyncMock(return_value={
            "open_id": "ou_super_admin", "user_id": "super_admin_user_id", "is_super_admin": True,
        })
        service.store.save_member = AsyncMock()
        service.store.delete_member = AsyncMock()
        app = FastAPI()
        register_auth(app, service)
        request = self.request(method="PUT", path="/api/admin/members/ou_super_admin")
        save = endpoint(app, "/api/admin/members/{open_id}", "PUT")
        delete = endpoint(app, "/api/admin/members/{open_id}", "DELETE")
        with self.assertRaises(HTTPException) as downgrade_error:
            asyncio.run(save(request, "ou_super_admin", {"role": "member", "status": "active"}))
        with self.assertRaises(HTTPException) as delete_error:
            asyncio.run(delete(request, "ou_super_admin"))
        self.assertEqual(downgrade_error.exception.status_code, 400)
        self.assertEqual(delete_error.exception.status_code, 400)
        service.store.save_member.assert_not_awaited()
        service.store.delete_member.assert_not_awaited()

    def test_logout_deletes_session_cookie(self):
        service = AuthService(settings())
        app = FastAPI()
        register_auth(app, service)
        logout = endpoint(app, "/api/auth/logout", "POST")
        response = asyncio.run(logout())
        self.assertEqual(response.status_code, 302)
        self.assertIn('fy_session=""', response.headers.get("set-cookie", ""))


if __name__ == "__main__":
    unittest.main()
