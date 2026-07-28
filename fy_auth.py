import base64
import asyncio
from contextlib import closing
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set

import httpx
from fastapi import Body, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse


FEISHU_OPEN_API = "https://open.feishu.cn/open-apis"
FEISHU_AUTHORIZE_URL = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
SESSION_COOKIE = "fy_session"
OAUTH_STATE_COOKIE = "fy_oauth_state"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CORE_MENU_PERMISSIONS = [
    "menu:text-to-image",
    "menu:enhance",
    "menu:image-edit",
    "menu:angle",
    "menu:online",
    "menu:gpt-chat",
    "menu:canvas",
    "menu:asset-manager",
]

DEFAULT_ROLES: Dict[str, Dict[str, Any]] = {
    "admin": {
        "name": "admin",
        "display_name": "管理员",
        "permissions": CORE_MENU_PERMISSIONS + [
            "menu:api-settings",
            "menu:more-settings",
            "menu:workflow-settings",
            "menu:organization-permissions",
            "action:read",
            "action:write",
            "settings:api:manage",
            "settings:more:manage",
            "organization:view",
        ],
        "system": True,
    },
    "member": {
        "name": "member",
        "display_name": "成员",
        "permissions": CORE_MENU_PERMISSIONS + ["action:read", "action:write"],
        "system": True,
    },
    "guest": {
        "name": "guest",
        "display_name": "访客",
        "permissions": CORE_MENU_PERMISSIONS + ["action:read"],
        "system": True,
    },
}


class FeishuAPIError(RuntimeError):
    pass


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str) -> List[str]:
    return [item.strip() for item in os.getenv(name, "").split(",") if item.strip()]


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _field_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return ",".join(filter(None, (_field_text(item) for item in value)))
    if isinstance(value, dict):
        for key in ("text", "name", "value", "id"):
            if key in value:
                return _field_text(value.get(key))
    return str(value).strip()


def _field_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _field_text(value).lower() in {"1", "true", "yes", "on"}


def _identity_values(user: Optional[Dict[str, Any]]) -> Set[str]:
    if not user:
        return set()
    values = {
        _field_text(user.get(key))
        for key in ("open_id", "user_id", "union_id", "email", "mobile")
    }
    values.discard("")
    return values


def _json_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = _field_text(value)
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except (TypeError, ValueError):
        pass
    return [item.strip() for item in text.split(",") if item.strip()]


@dataclass(frozen=True)
class AuthSettings:
    app_id: str
    app_secret: str
    redirect_uri: str
    redirect_uris: List[str]
    session_secret: str
    super_admin_ids: List[str]
    bitable_app_token: str
    members_table_id: str
    roles_table_id: str
    cookie_secure: bool
    default_role: str
    local_auth_enabled: bool = True
    auth_db_path: str = ""
    permission_store: str = "bitable"

    @classmethod
    def from_env(cls) -> "AuthSettings":
        app_id = os.getenv("FEISHU_APP_ID", "").strip()
        app_secret = os.getenv("FEISHU_APP_SECRET", "").strip()
        session_secret = os.getenv("FY_SESSION_SECRET", "").strip()
        if not session_secret and app_secret:
            session_secret = hashlib.sha256(("fy-session:" + app_secret).encode("utf-8")).hexdigest()
        if not session_secret:
            session_secret = secrets.token_urlsafe(32)
        redirect_uri = os.getenv("FEISHU_REDIRECT_URI", "").strip()
        redirect_uris = _csv_env("FEISHU_REDIRECT_URIS")
        redirect_uris = list(dict.fromkeys([item for item in [redirect_uri, *redirect_uris] if item]))
        return cls(
            app_id=app_id,
            app_secret=app_secret,
            redirect_uri=redirect_uris[0] if redirect_uris else "",
            redirect_uris=redirect_uris,
            session_secret=session_secret,
            super_admin_ids=_csv_env("FY_SUPER_ADMIN_IDS"),
            bitable_app_token=os.getenv("FEISHU_BITABLE_APP_TOKEN", "").strip(),
            members_table_id=os.getenv("FEISHU_BITABLE_MEMBERS_TABLE_ID", "").strip(),
            roles_table_id=os.getenv("FEISHU_BITABLE_ROLES_TABLE_ID", "").strip(),
            cookie_secure=_bool_env("FY_COOKIE_SECURE", False),
            default_role="member",
            local_auth_enabled=_bool_env("FY_LOCAL_AUTH_ENABLED", True),
            auth_db_path=os.getenv("FY_AUTH_DB_PATH", "").strip(),
            permission_store=os.getenv("FY_PERMISSION_STORE", "local").strip().lower() or "local",
        )

    @property
    def allowed_redirect_uris(self) -> List[str]:
        return list(dict.fromkeys([item for item in [self.redirect_uri, *self.redirect_uris] if item]))

    @property
    def sso_configured(self) -> bool:
        return bool(self.app_id and self.app_secret and self.allowed_redirect_uris and self.super_admin_ids)

    @property
    def bitable_configured(self) -> bool:
        return bool(self.bitable_app_token and self.members_table_id and self.roles_table_id)

    def missing_sso_fields(self) -> List[str]:
        values = {
            "FEISHU_APP_ID": self.app_id,
            "FEISHU_APP_SECRET": self.app_secret,
            "FEISHU_REDIRECT_URIS": self.allowed_redirect_uris,
            "FY_SUPER_ADMIN_IDS": self.super_admin_ids,
        }
        return [key for key, value in values.items() if not value]

    def missing_bitable_fields(self) -> List[str]:
        values = {
            "FEISHU_BITABLE_APP_TOKEN": self.bitable_app_token,
            "FEISHU_BITABLE_MEMBERS_TABLE_ID": self.members_table_id,
            "FEISHU_BITABLE_ROLES_TABLE_ID": self.roles_table_id,
        }
        return [key for key, value in values.items() if not value]


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64encode(salt)}${_b64encode(digest)}"


def _password_matches(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64decode(salt), int(iterations)
        )
        return hmac.compare_digest(_b64encode(actual), expected)
    except (TypeError, ValueError):
        return False


LOCAL_ACCOUNT_VALIDITY_DAYS = 30


def _expiry_timestamp(value: Any = None) -> float:
    if value in (None, ""):
        return time.time() + LOCAL_ACCOUNT_VALIDITY_DAYS * 24 * 60 * 60
    if isinstance(value, (int, float)):
        return float(value)
    text = _field_text(value)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("到期日期格式无效") from exc
    if len(text) == 10:
        parsed = parsed + timedelta(days=1) - timedelta(seconds=1)
    return parsed.timestamp()


class LocalAccountStore:
    """Small SQLite store for non-Feishu users; secrets never leave this process."""

    def __init__(self, settings: AuthSettings):
        configured = settings.auth_db_path or os.getenv("FY_AUTH_DB_PATH", "").strip()
        self.path = configured or os.path.join(os.path.dirname(__file__), "data", "fy_auth.db")

    def _connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS local_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'guest',
                status TEXT NOT NULL DEFAULT 'active',
                tenant_key TEXT NOT NULL DEFAULT '',
                expires_at REAL NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )"""
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(local_accounts)").fetchall()}
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE local_accounts ADD COLUMN expires_at REAL")
            conn.execute(
                "UPDATE local_accounts SET expires_at = ? WHERE expires_at IS NULL",
                (_expiry_timestamp(),),
            )
        conn.commit()
        return conn

    @staticmethod
    def _disable_expired(conn: sqlite3.Connection) -> None:
        conn.execute(
            "UPDATE local_accounts SET status = 'disabled', updated_at = ? WHERE status = 'active' AND expires_at <= ?",
            (time.time(), time.time()),
        )
        conn.commit()

    @staticmethod
    def _row(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        result = dict(row)
        result.pop("password_hash", None)
        return result

    def get(self, account_id: int) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            row = conn.execute("SELECT * FROM local_accounts WHERE id = ?", (int(account_id),)).fetchone()
        return self._row(row)

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            row = conn.execute("SELECT * FROM local_accounts WHERE username = ?", (username.strip(),)).fetchone()
        if row is None or row["status"] != "active" or not _password_matches(password, row["password_hash"]):
            return None
        return self._row(row)

    def create(self, username: str, display_name: str, password: str, role: str, tenant_key: str = "", expires_at: Any = None) -> Dict[str, Any]:
        now = time.time()
        expires_at_value = _expiry_timestamp(expires_at)
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                "INSERT INTO local_accounts (username, display_name, password_hash, role, tenant_key, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username.strip(), display_name.strip(), _password_hash(password), role, tenant_key.strip(), expires_at_value, now, now),
            )
            account_id = cursor.lastrowid
            conn.commit()
        return self.get(int(account_id)) or {}

    def list(self) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            rows = conn.execute("SELECT * FROM local_accounts ORDER BY id").fetchall()
        return [self._row(row) for row in rows if row is not None]

    def update(self, account_id: int, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {key: fields[key] for key in ("display_name", "role", "status", "tenant_key", "expires_at") if key in fields}
        if "password" in fields and fields["password"]:
            allowed["password_hash"] = _password_hash(str(fields["password"]))
        if not allowed:
            return self.get(account_id)
        allowed["updated_at"] = time.time()
        assignments = ", ".join(f"{key} = ?" for key in allowed)
        with closing(self._connect()) as conn:
            conn.execute(f"UPDATE local_accounts SET {assignments} WHERE id = ?", (*allowed.values(), int(account_id)))
            conn.commit()
        return self.get(account_id)

    def delete(self, account_id: int) -> bool:
        with closing(self._connect()) as conn:
            cursor = conn.execute("DELETE FROM local_accounts WHERE id = ?", (int(account_id),))
            conn.commit()
        return cursor.rowcount > 0


class SignedTokenCodec:
    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def encode(self, payload: Dict[str, Any], ttl_seconds: int) -> str:
        data = dict(payload)
        data["exp"] = int(time.time()) + int(ttl_seconds)
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = hmac.new(self.secret, raw, hashlib.sha256).digest()
        return f"{_b64encode(raw)}.{_b64encode(signature)}"

    def decode(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            raw_part, signature_part = token.split(".", 1)
            raw = _b64decode(raw_part)
            signature = _b64decode(signature_part)
            expected = hmac.new(self.secret, raw, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                return None
            payload = json.loads(raw.decode("utf-8"))
            if int(payload.get("exp") or 0) < int(time.time()):
                return None
            return payload
        except (ValueError, TypeError, json.JSONDecodeError):
            return None


class FeishuClient:
    def __init__(self, settings: AuthSettings):
        self.settings = settings
        self._tenant_token = ""
        self._tenant_token_expires_at = 0.0

    async def _request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.request(method, url, **kwargs)
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise FeishuAPIError(f"飞书接口请求失败：{exc}") from exc
        code = payload.get("code", 0) if isinstance(payload, dict) else -1
        if code not in (0, None):
            raise FeishuAPIError(payload.get("msg") or payload.get("message") or f"飞书接口错误 code={code}")
        return payload

    async def tenant_access_token(self) -> str:
        if self._tenant_token and time.time() < self._tenant_token_expires_at:
            return self._tenant_token
        payload = await self._request(
            "POST",
            f"{FEISHU_OPEN_API}/auth/v3/tenant_access_token/internal",
            json={"app_id": self.settings.app_id, "app_secret": self.settings.app_secret},
        )
        token = payload.get("tenant_access_token") or (payload.get("data") or {}).get("tenant_access_token")
        if not token:
            raise FeishuAPIError("飞书未返回 tenant_access_token")
        expires = int(payload.get("expire") or (payload.get("data") or {}).get("expire") or 7200)
        self._tenant_token = str(token)
        self._tenant_token_expires_at = time.time() + max(60, expires - 120)
        return self._tenant_token

    async def tenant_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {await self.tenant_access_token()}"}

    def authorize_url(self, state: str, redirect_uri: str = "") -> str:
        params = {
            "app_id": self.settings.app_id,
            "redirect_uri": redirect_uri or self.settings.redirect_uri,
            "state": state,
        }
        return f"{FEISHU_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, code: str, redirect_uri: str = "") -> Dict[str, Any]:
        payload = await self._request(
            "POST",
            f"{FEISHU_OPEN_API}/authen/v2/oauth/token",
            json={
                "grant_type": "authorization_code",
                "client_id": self.settings.app_id,
                "client_secret": self.settings.app_secret,
                "code": code,
                "redirect_uri": redirect_uri or self.settings.redirect_uri,
            },
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        token_data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        user = token_data.get("user_info") if isinstance(token_data.get("user_info"), dict) else None
        if user is None:
            access_token = _field_text(token_data.get("access_token"))
            if access_token:
                profile_payload = await self._request(
                    "GET",
                    f"{FEISHU_OPEN_API}/authen/v1/user_info",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                profile_data = (
                    profile_payload.get("data")
                    if isinstance(profile_payload.get("data"), dict)
                    else profile_payload
                )
                user = (
                    profile_data.get("user_info")
                    if isinstance(profile_data.get("user_info"), dict)
                    else profile_data
                )
        user = user if isinstance(user, dict) else token_data
        result = {
            "open_id": _field_text(user.get("open_id") or token_data.get("open_id")),
            "union_id": _field_text(user.get("union_id") or token_data.get("union_id")),
            "user_id": _field_text(user.get("user_id") or token_data.get("user_id")),
            "tenant_key": _field_text(user.get("tenant_key") or token_data.get("tenant_key")),
            "name": _field_text(user.get("name") or token_data.get("name")),
            "email": _field_text(user.get("email") or token_data.get("email")),
            "mobile": _field_text(user.get("mobile") or token_data.get("mobile")),
            "avatar_url": _field_text(user.get("avatar_url") or token_data.get("avatar_url")),
            "is_tenant_manager": _field_bool(
                user.get("is_tenant_manager") or token_data.get("is_tenant_manager")
            ),
        }
        if not result["open_id"] and not result["user_id"]:
            raise FeishuAPIError("飞书登录响应缺少用户标识，请检查应用的登录权限")
        return result

    async def get_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        identifier = _field_text(user.get("open_id"))
        user_id_type = "open_id"
        if not identifier:
            identifier = _field_text(user.get("user_id"))
            user_id_type = "user_id"
        if not identifier:
            return dict(user)
        payload = await self._request(
            "GET",
            f"{FEISHU_OPEN_API}/contact/v3/users/{urllib.parse.quote(identifier, safe='')}",
            params={"user_id_type": user_id_type},
            headers=await self.tenant_headers(),
        )
        detail = (payload.get("data") or {}).get("user") or {}
        merged = dict(user)
        for key in ("open_id", "union_id", "user_id", "name", "email", "mobile", "avatar_url", "tenant_key"):
            value = detail.get(key)
            if value not in (None, ""):
                merged[key] = value
        merged["is_tenant_manager"] = _field_bool(detail.get("is_tenant_manager") or merged.get("is_tenant_manager"))
        return merged

    async def paged_get(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        page_token = ""
        while True:
            query = dict(params or {})
            if page_token:
                query["page_token"] = page_token
            payload = await self._request(
                "GET",
                f"{FEISHU_OPEN_API}{path}",
                params=query,
                headers=await self.tenant_headers(),
            )
            data = payload.get("data") or {}
            items.extend(data.get("items") or [])
            if not data.get("has_more"):
                return items
            page_token = _field_text(data.get("page_token"))
            if not page_token:
                return items

    async def list_departments(self) -> List[Dict[str, Any]]:
        return await self.paged_get(
            "/contact/v3/departments/0/children",
            {"fetch_child": "true", "page_size": 50, "department_id_type": "open_department_id"},
        )

    async def list_users_for_department(self, department_id: str) -> List[Dict[str, Any]]:
        return await self.paged_get(
            "/contact/v3/users/find_by_department",
            {
                "department_id": department_id,
                "department_id_type": "open_department_id",
                "user_id_type": "open_id",
                "page_size": 50,
            },
        )


class BitablePermissionStore:
    MEMBER_FIELDS = {
        "open_id": "Open ID",
        "user_id": "User ID",
        "name": "Name",
        "email": "Email",
        "department_ids": "Department IDs",
        "role": "Role",
        "status": "Status",
        "updated_at": "Updated At",
    }
    ROLE_FIELDS = {
        "name": "Role",
        "display_name": "Display Name",
        "permissions": "Permissions",
        "system": "System",
        "updated_at": "Updated At",
    }

    def __init__(self, settings: AuthSettings, client: FeishuClient):
        self.settings = settings
        self.client = client
        self._cache: Dict[str, Any] = {}
        self._cache_expires_at = 0.0

    @property
    def configured(self) -> bool:
        return self.settings.bitable_configured

    async def _list_records(self, table_id: str) -> List[Dict[str, Any]]:
        return await self.client.paged_get(
            f"/bitable/v1/apps/{self.settings.bitable_app_token}/tables/{table_id}/records",
            {"page_size": 100},
        )

    def _member_from_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        fields = record.get("fields") or {}
        return {
            "record_id": record.get("record_id") or "",
            "open_id": _field_text(fields.get(self.MEMBER_FIELDS["open_id"])),
            "user_id": _field_text(fields.get(self.MEMBER_FIELDS["user_id"])),
            "name": _field_text(fields.get(self.MEMBER_FIELDS["name"])),
            "email": _field_text(fields.get(self.MEMBER_FIELDS["email"])),
            "department_ids": _json_list(fields.get(self.MEMBER_FIELDS["department_ids"])),
            "role": _field_text(fields.get(self.MEMBER_FIELDS["role"])).lower(),
            "status": _field_text(fields.get(self.MEMBER_FIELDS["status"])).lower() or "active",
        }

    def _role_from_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        fields = record.get("fields") or {}
        name = _field_text(fields.get(self.ROLE_FIELDS["name"])).lower()
        return {
            "record_id": record.get("record_id") or "",
            "name": name,
            "display_name": _field_text(fields.get(self.ROLE_FIELDS["display_name"])) or name,
            "permissions": _json_list(fields.get(self.ROLE_FIELDS["permissions"])),
            "system": _field_text(fields.get(self.ROLE_FIELDS["system"])).lower() in {"1", "true", "yes"},
        }

    async def snapshot(self, refresh: bool = False) -> Dict[str, Any]:
        if not self.configured:
            return {"members": [], "roles": dict(DEFAULT_ROLES), "source": "defaults"}
        if not refresh and self._cache and time.time() < self._cache_expires_at:
            return self._cache
        member_records, role_records = await self._list_records(self.settings.members_table_id), await self._list_records(self.settings.roles_table_id)
        members = [self._member_from_record(record) for record in member_records]
        roles = {name: dict(role) for name, role in DEFAULT_ROLES.items()}
        for record in role_records:
            role = self._role_from_record(record)
            if role["name"]:
                roles[role["name"]] = role
        self._cache = {"members": members, "roles": roles, "source": "bitable"}
        self._cache_expires_at = time.time() + 30
        return self._cache

    async def member_for(self, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        snapshot = await self.snapshot()
        candidates = {str(user.get(key) or "").strip() for key in ("open_id", "user_id", "email", "mobile")}
        candidates.discard("")
        for member in snapshot["members"]:
            identifiers = {str(member.get(key) or "").strip() for key in ("open_id", "user_id", "email")}
            if candidates.intersection(identifiers):
                return member
        return None

    async def role_map(self) -> Dict[str, Dict[str, Any]]:
        return (await self.snapshot())["roles"]

    async def _write_record(self, table_id: str, fields: Dict[str, Any], record_id: str = "") -> Dict[str, Any]:
        base = f"{FEISHU_OPEN_API}/bitable/v1/apps/{self.settings.bitable_app_token}/tables/{table_id}/records"
        method = "PUT" if record_id else "POST"
        url = f"{base}/{record_id}" if record_id else base
        payload = await self.client._request(method, url, json={"fields": fields}, headers=await self.client.tenant_headers())
        self._cache_expires_at = 0
        return (payload.get("data") or {}).get("record") or payload.get("data") or {}

    async def save_member(self, member: Dict[str, Any]) -> Dict[str, Any]:
        if not self.configured:
            raise FeishuAPIError("未配置飞书多维表格")
        existing = await self.member_for(member)
        fields = {
            self.MEMBER_FIELDS["open_id"]: _field_text(member.get("open_id")),
            self.MEMBER_FIELDS["user_id"]: _field_text(member.get("user_id")),
            self.MEMBER_FIELDS["name"]: _field_text(member.get("name")),
            self.MEMBER_FIELDS["email"]: _field_text(member.get("email")),
            self.MEMBER_FIELDS["department_ids"]: json.dumps(member.get("department_ids") or [], ensure_ascii=False),
            self.MEMBER_FIELDS["role"]: _field_text(member.get("role")) or self.settings.default_role,
            self.MEMBER_FIELDS["status"]: _field_text(member.get("status")) or "active",
            self.MEMBER_FIELDS["updated_at"]: int(time.time() * 1000),
        }
        return await self._write_record(
            self.settings.members_table_id,
            fields,
            (existing or {}).get("record_id") or _field_text(member.get("record_id")),
        )

    async def delete_member(self, member: Dict[str, Any]) -> bool:
        if not self.configured:
            raise FeishuAPIError("未配置飞书多维表格")
        existing = await self.member_for(member)
        record_id = _field_text((existing or {}).get("record_id"))
        if not record_id:
            return False
        url = (
            f"{FEISHU_OPEN_API}/bitable/v1/apps/{self.settings.bitable_app_token}"
            f"/tables/{self.settings.members_table_id}/records/{record_id}"
        )
        await self.client._request("DELETE", url, headers=await self.client.tenant_headers())
        self._cache_expires_at = 0
        return True

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        if not self.configured:
            raise FeishuAPIError("未配置飞书多维表格")
        roles = await self.role_map()
        existing = roles.get(_field_text(role.get("name")).lower()) or {}
        fields = {
            self.ROLE_FIELDS["name"]: _field_text(role.get("name")).lower(),
            self.ROLE_FIELDS["display_name"]: _field_text(role.get("display_name")),
            self.ROLE_FIELDS["permissions"]: json.dumps(role.get("permissions") or [], ensure_ascii=False),
            self.ROLE_FIELDS["system"]: bool(role.get("system")),
            self.ROLE_FIELDS["updated_at"]: int(time.time() * 1000),
        }
        return await self._write_record(self.settings.roles_table_id, fields, existing.get("record_id") or "")


class LocalPermissionStore:
    """Application-owned permission store; it deliberately has no Feishu API client."""

    def __init__(self, settings: AuthSettings):
        configured = settings.auth_db_path or os.getenv("FY_AUTH_DB_PATH", "").strip()
        self.path = configured or os.path.join(os.path.dirname(__file__), "data", "fy_auth.db")
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_expires_at = 0.0

    def _connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS permission_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_key TEXT NOT NULL DEFAULT '',
                open_id TEXT NOT NULL DEFAULT '',
                user_id TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                mobile TEXT NOT NULL DEFAULT '',
                department_ids TEXT NOT NULL DEFAULT '[]',
                role TEXT NOT NULL DEFAULT 'member',
                status TEXT NOT NULL DEFAULT 'active',
                updated_at REAL NOT NULL,
                UNIQUE (tenant_key, open_id, user_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS permission_roles (
                name TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                permissions TEXT NOT NULL DEFAULT '[]',
                system INTEGER NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            )"""
        )
        conn.commit()
        return conn

    @staticmethod
    def _member(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        result = dict(row)
        result["department_ids"] = _json_list(result.get("department_ids"))
        result.pop("id", None)
        return result

    @staticmethod
    def _role(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        result = dict(row)
        result["permissions"] = _json_list(result.get("permissions"))
        result["system"] = bool(result.get("system"))
        return result

    async def snapshot(self, refresh: bool = False) -> Dict[str, Any]:
        if not refresh and self._cache and time.time() < self._cache_expires_at:
            return self._cache
        with closing(self._connect()) as conn:
            member_rows = conn.execute("SELECT * FROM permission_members ORDER BY id").fetchall()
            role_rows = conn.execute("SELECT * FROM permission_roles ORDER BY name").fetchall()
        roles = {name: dict(role) for name, role in DEFAULT_ROLES.items()}
        for row in role_rows:
            role = self._role(row)
            if role and role.get("name"):
                roles[role["name"]] = role
        self._cache = {
            "members": [self._member(row) for row in member_rows],
            "roles": roles,
            "source": "local",
        }
        self._cache_expires_at = time.time() + 30
        return self._cache

    @property
    def configured(self) -> bool:
        return True

    async def member_for(self, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        candidates = {str(user.get(key) or "").strip() for key in ("open_id", "user_id", "email", "mobile")}
        candidates.discard("")
        tenant_key = _field_text(user.get("tenant_key"))
        snapshot = await self.snapshot()
        for member in snapshot["members"]:
            if tenant_key and member.get("tenant_key") and member.get("tenant_key") != tenant_key:
                continue
            identifiers = {str(member.get(key) or "").strip() for key in ("open_id", "user_id", "email", "mobile")}
            if candidates.intersection(identifiers):
                return member
        return None

    async def role_map(self) -> Dict[str, Dict[str, Any]]:
        return (await self.snapshot())["roles"]

    async def save_member(self, member: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        normalized = {
            "tenant_key": _field_text(member.get("tenant_key")),
            "open_id": _field_text(member.get("open_id")),
            "user_id": _field_text(member.get("user_id")),
            "name": _field_text(member.get("name")),
            "email": _field_text(member.get("email")),
            "mobile": _field_text(member.get("mobile")),
            "department_ids": _json_list(member.get("department_ids")),
            "role": _field_text(member.get("role") or "member").lower(),
            "status": _field_text(member.get("status") or "active").lower(),
        }
        with closing(self._connect()) as conn:
            existing = await self.member_for(normalized)
            if existing:
                conn.execute(
                    """UPDATE permission_members SET tenant_key=?, open_id=?, user_id=?, name=?, email=?, mobile=?,
                       department_ids=?, role=?, status=?, updated_at=? WHERE tenant_key=? AND open_id=? AND user_id=?""",
                    (
                        normalized["tenant_key"], normalized["open_id"], normalized["user_id"], normalized["name"],
                        normalized["email"], normalized["mobile"], json.dumps(normalized["department_ids"], ensure_ascii=False),
                        normalized["role"], normalized["status"], now, existing.get("tenant_key", ""),
                        existing.get("open_id", ""), existing.get("user_id", ""),
                    ),
                )
            else:
                conn.execute(
                    """INSERT INTO permission_members
                       (tenant_key, open_id, user_id, name, email, mobile, department_ids, role, status, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        normalized["tenant_key"], normalized["open_id"], normalized["user_id"], normalized["name"],
                        normalized["email"], normalized["mobile"], json.dumps(normalized["department_ids"], ensure_ascii=False),
                        normalized["role"], normalized["status"], now,
                    ),
                )
            conn.commit()
        self._cache = None
        return normalized

    async def delete_member(self, member: Dict[str, Any]) -> bool:
        existing = await self.member_for(member)
        if not existing:
            return False
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                "DELETE FROM permission_members WHERE tenant_key=? AND open_id=? AND user_id=?",
                (existing.get("tenant_key", ""), existing.get("open_id", ""), existing.get("user_id", "")),
            )
            conn.commit()
        self._cache = None
        return cursor.rowcount > 0

    async def save_role(self, role: Dict[str, Any]) -> Dict[str, Any]:
        name = _field_text(role.get("name")).lower()
        normalized = {
            "name": name,
            "display_name": _field_text(role.get("display_name")) or name,
            "permissions": _json_list(role.get("permissions")),
            "system": bool(role.get("system")),
            "updated_at": time.time(),
        }
        with closing(self._connect()) as conn:
            conn.execute(
                """INSERT INTO permission_roles (name, display_name, permissions, system, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET display_name=excluded.display_name,
                   permissions=excluded.permissions, system=excluded.system, updated_at=excluded.updated_at""",
                (name, normalized["display_name"], json.dumps(normalized["permissions"], ensure_ascii=False), normalized["system"], normalized["updated_at"]),
            )
            conn.commit()
        self._cache = None
        return normalized


class AuthService:
    def __init__(self, settings: Optional[AuthSettings] = None):
        self.settings = settings or AuthSettings.from_env()
        self.codec = SignedTokenCodec(self.settings.session_secret)
        self.feishu = FeishuClient(self.settings)
        self.store = (
            LocalPermissionStore(self.settings)
            if self.settings.permission_store == "local"
            else BitablePermissionStore(self.settings, self.feishu)
        )
        self.local_accounts = LocalAccountStore(self.settings)
        self._local_login_failures: Dict[str, List[float]] = {}
        self._organization_cache: Dict[str, Any] = {}
        self._organization_expires_at = 0.0

    def is_super_admin(self, user: Dict[str, Any]) -> bool:
        expected = set(self.settings.super_admin_ids)
        return bool(expected.intersection(_identity_values(user)))

    async def resolve_profile(self, user: Dict[str, Any]) -> Dict[str, Any]:
        profile = dict(user)
        local_account = None
        if profile.get("auth_type") == "local" or profile.get("local_account_id"):
            if not self.settings.local_auth_enabled:
                return {"status": "disabled", "auth_type": "local"}
            try:
                local_account = self.local_accounts.get(int(profile.get("local_account_id") or 0))
            except (TypeError, ValueError):
                local_account = None
            if not local_account:
                return {"status": "disabled", "auth_type": "local"}
            profile.update(local_account)
            profile["auth_type"] = "local"
            profile["name"] = profile.get("name") or profile.get("display_name") or profile.get("username")
        super_admin = self.is_super_admin(profile)
        member = None
        if not local_account and self.store.configured:
            try:
                member = await self.store.member_for(profile)
            except FeishuAPIError as exc:
                profile["permission_sync_error"] = str(exc)
        role_name = "admin" if super_admin else _field_text((member or {}).get("role") or profile.get("role") or self.settings.default_role).lower()
        roles = dict(DEFAULT_ROLES)
        if self.store.configured:
            try:
                roles = await self.store.role_map()
            except FeishuAPIError as exc:
                profile["permission_sync_error"] = str(exc)
        role = roles.get(role_name) or roles.get(self.settings.default_role) or DEFAULT_ROLES["member"]
        permissions = list(role.get("permissions") or [])
        if super_admin:
            permissions = sorted({permission for item in roles.values() for permission in item.get("permissions") or []})
            permissions.extend(["organization:manage", "roles:manage"])
        profile.update({
            "role": role_name,
            "permissions": sorted(set(permissions)),
            "is_super_admin": super_admin,
            "read_only": role_name == "guest" or "action:write" not in permissions,
            "status": "active" if super_admin else (
                (local_account or {}).get("status") if local_account else (member or {}).get("status")
            ) or "active",
        })
        return profile

    async def authenticate_local(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        if not self.settings.local_auth_enabled:
            return None
        key = username.strip().casefold()
        now = time.time()
        recent = [item for item in self._local_login_failures.get(key, []) if now - item < 600]
        if len(recent) >= 5:
            self._local_login_failures[key] = recent
            return None
        account = self.local_accounts.authenticate(username, password)
        if not account:
            recent.append(now)
            self._local_login_failures[key] = recent[-5:]
            return None
        self._local_login_failures.pop(key, None)
        return await self.resolve_profile({
            "auth_type": "local",
            "local_account_id": account["id"],
        })

    async def current_user(self, request: Request) -> Optional[Dict[str, Any]]:
        cached = getattr(request.state, "fy_user", None)
        if cached is not None:
            return cached
        token = request.cookies.get(SESSION_COOKIE, "")
        payload = self.codec.decode(token) if token else None
        if not payload or payload.get("kind") != "session":
            return None
        stored_user = dict(payload.get("user") or {})
        if payload.get("auth_type"):
            stored_user["auth_type"] = payload.get("auth_type")
        if payload.get("local_account_id"):
            stored_user["local_account_id"] = payload.get("local_account_id")
        user = await self.resolve_profile(stored_user)
        if user.get("status") == "disabled":
            return None
        request.state.fy_user = user
        return user

    @staticmethod
    def has_permission(user: Optional[Dict[str, Any]], permission: str) -> bool:
        if not user:
            return False
        if user.get("is_super_admin"):
            return True
        return permission in set(user.get("permissions") or [])

    def public_config(self) -> Dict[str, Any]:
        permission_store = "local" if isinstance(self.store, LocalPermissionStore) else "bitable"
        return {
            "sso_enabled": True,
            "sso_configured": self.settings.sso_configured,
            "local_auth_enabled": self.settings.local_auth_enabled,
            "permission_store": permission_store,
            "bitable_enabled": permission_store == "bitable" and self.settings.bitable_configured,
            "missing_sso_fields": self.settings.missing_sso_fields(),
            "missing_bitable_fields": self.settings.missing_bitable_fields(),
            "default_role": self.settings.default_role,
        }

    def redirect_uri_for_request(self, request: Request) -> str:
        allowed = self.settings.allowed_redirect_uris
        if not allowed:
            return ""
        request_origin = f"{request.url.scheme}://{request.url.netloc}".lower()
        for candidate in allowed:
            parsed = urllib.parse.urlsplit(candidate)
            candidate_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            if candidate_origin == request_origin:
                return candidate
        return allowed[0]

    async def organization(self, current_user: Optional[Dict[str, Any]] = None, refresh: bool = False) -> Dict[str, Any]:
        if refresh or not self._organization_cache or time.time() >= self._organization_expires_at:
            departments = await self.feishu.list_departments()
            department_ids = [
                _field_text(item.get("open_department_id") or item.get("department_id"))
                for item in departments
            ]
            department_ids = [item for item in department_ids if item]
            users_by_id: Dict[str, Dict[str, Any]] = {}
            semaphore = asyncio.Semaphore(5)

            async def load_department_users(department_id: str):
                async with semaphore:
                    users = await self.feishu.list_users_for_department(department_id)
                    return department_id, users

            unique_department_ids = list(dict.fromkeys(["0", *department_ids]))
            user_groups = await asyncio.gather(*(load_department_users(item) for item in unique_department_ids))
            for department_id, users_in_department in user_groups:
                for directory_user in users_in_department:
                    key = _field_text(directory_user.get("open_id") or directory_user.get("user_id"))
                    if key:
                        existing = users_by_id.get(key) or {}
                        merged = {**existing, **directory_user}
                        memberships = [
                            *_json_list(existing.get("department_ids")),
                            *_json_list(directory_user.get("department_ids")),
                        ]
                        if department_id != "0":
                            memberships.append(department_id)
                        merged["department_ids"] = list(dict.fromkeys(item for item in memberships if item))
                        users_by_id[key] = merged
            self._organization_cache = {
                "departments": departments,
                "directory_users": list(users_by_id.values()),
            }
            self._organization_expires_at = time.time() + 60

        departments = self._organization_cache.get("departments") or []
        directory_users = list(self._organization_cache.get("directory_users") or [])
        current_ids = _identity_values(current_user)
        if current_user and current_ids and not any(current_ids.intersection(_identity_values(item)) for item in directory_users):
            directory_users.append(current_user)
        snapshot = await self.store.snapshot()
        users = []
        for item in directory_users:
            assignment = next(
                (
                    member for member in snapshot["members"]
                    if _identity_values(item).intersection(_identity_values(member))
                ),
                {},
            )
            is_current = bool(current_ids.intersection(_identity_values(item)))
            is_super_admin = self.is_super_admin(item)
            users.append({
                "open_id": _field_text(item.get("open_id")),
                "user_id": _field_text(item.get("user_id")),
                "name": _field_text(item.get("name")),
                "email": _field_text(item.get("email")),
                "mobile": _field_text(item.get("mobile")),
                "department_ids": item.get("department_ids") or [],
                "role": "admin" if is_super_admin else assignment.get("role") or "member",
                "status": "active" if is_super_admin else assignment.get("status") or "active",
                "is_current": is_current,
                "is_super_admin": is_super_admin,
                "managed": bool(assignment),
            })
        result = {
            "departments": departments,
            "users": users,
            "roles": list(snapshot["roles"].values()),
            "source": snapshot["source"],
            "tenant_key": _field_text((current_user or {}).get("tenant_key")),
        }
        return result


def _return_path(value: str) -> str:
    text = str(value or "/").strip()
    if not text.startswith("/") or text.startswith("//"):
        return "/"
    return text


def register_auth(app, service: AuthService) -> None:
    async def auth_config():
        return service.public_config()

    async def auth_me(request: Request):
        user = await service.current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="请先登录")
        return {"user": user, "config": service.public_config()}

    async def local_login(request: Request, payload: Dict[str, Any] = Body(...)):
        if not service.settings.local_auth_enabled:
            raise HTTPException(status_code=404, detail="本地账号登录未启用")
        username = _field_text(payload.get("username"))
        password = _field_text(payload.get("password"))
        if not username or not password:
            raise HTTPException(status_code=400, detail="请输入账号和密码")
        user = await service.authenticate_local(username, password)
        if not user:
            raise HTTPException(status_code=401, detail="账号或密码错误，或账号已停用")
        session = service.codec.encode({
            "kind": "session",
            "auth_type": "local",
            "local_account_id": user["id"],
        }, 12 * 60 * 60)
        response = JSONResponse({"ok": True, "return_to": _return_path(payload.get("return_to") or "/")})
        response.set_cookie(
            SESSION_COOKIE,
            session,
            max_age=12 * 60 * 60,
            httponly=True,
            secure=service.settings.cookie_secure,
            samesite="lax",
        )
        return response

    async def auth_login(request: Request, return_to: str = "/"):
        if not service.settings.sso_configured:
            raise HTTPException(status_code=503, detail="飞书 SSO 缺少必要配置")
        redirect_uri = service.redirect_uri_for_request(request)
        nonce = secrets.token_urlsafe(24)
        state = service.codec.encode({
            "kind": "oauth",
            "nonce": nonce,
            "return_to": _return_path(return_to),
            "redirect_uri": redirect_uri,
        }, 600)
        response = RedirectResponse(service.feishu.authorize_url(state, redirect_uri), status_code=302)
        response.set_cookie(
            OAUTH_STATE_COOKIE,
            state,
            max_age=600,
            httponly=True,
            secure=service.settings.cookie_secure,
            samesite="lax",
        )
        return response

    async def auth_callback(request: Request, code: str = "", state: str = ""):
        cookie_state = request.cookies.get(OAUTH_STATE_COOKIE, "")
        state_payload = service.codec.decode(state) if state and hmac.compare_digest(state, cookie_state) else None
        if not code or not state_payload or state_payload.get("kind") != "oauth":
            raise HTTPException(status_code=400, detail="飞书登录状态无效或已过期，请重新登录")
        redirect_uri = _field_text(state_payload.get("redirect_uri"))
        if redirect_uri not in service.settings.allowed_redirect_uris:
            raise HTTPException(status_code=400, detail="飞书登录回调地址无效，请重新登录")
        try:
            user = await service.feishu.exchange_code(code, redirect_uri)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        try:
            user = await service.feishu.get_user(user)
        except FeishuAPIError:
            # OAuth already supplied a verified identity. Contact permissions are
            # optional for sign-in and only enrich the profile/organization view.
            pass
        session = service.codec.encode({"kind": "session", "user": user}, 12 * 60 * 60)
        response = RedirectResponse(_return_path(state_payload.get("return_to") or "/"), status_code=302)
        response.set_cookie(
            SESSION_COOKIE,
            session,
            max_age=12 * 60 * 60,
            httponly=True,
            secure=service.settings.cookie_secure,
            samesite="lax",
        )
        response.delete_cookie(OAUTH_STATE_COOKIE)
        return response

    async def auth_logout():
        response = RedirectResponse("/static/login.html", status_code=302)
        response.delete_cookie(SESSION_COOKIE)
        return response

    async def local_accounts(request: Request):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以管理外部账号")
        return {"accounts": service.local_accounts.list()}

    async def create_local_account(request: Request, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以管理外部账号")
        username = _field_text(payload.get("username"))
        display_name = _field_text(payload.get("display_name") or payload.get("name"))
        password = _field_text(payload.get("password"))
        role = _field_text(payload.get("role") or "guest").lower()
        if len(username) < 3 or len(username) > 64 or not all(char.isalnum() or char in "._-@+" for char in username):
            raise HTTPException(status_code=400, detail="账号格式无效")
        if len(display_name) > 80 or not display_name:
            raise HTTPException(status_code=400, detail="请填写展示名称")
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="密码至少需要 8 个字符")
        try:
            expires_at = _expiry_timestamp(payload.get("expires_at"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if expires_at <= time.time():
            raise HTTPException(status_code=400, detail="到期日期必须晚于当前时间")
        try:
            roles = await service.store.role_map() if service.store.configured else DEFAULT_ROLES
            if role not in roles:
                raise HTTPException(status_code=400, detail="账号角色不存在")
            return service.local_accounts.create(
                username, display_name, password, role, _field_text(user.get("tenant_key")), expires_at
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="账号已存在") from exc

    async def update_local_account(request: Request, account_id: int, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以管理外部账号")
        existing = service.local_accounts.get(account_id)
        if not existing:
            raise HTTPException(status_code=404, detail="账号不存在")
        fields = {}
        if "display_name" in payload:
            display_name = _field_text(payload.get("display_name"))
            if not display_name or len(display_name) > 80:
                raise HTTPException(status_code=400, detail="展示名称无效")
            fields["display_name"] = display_name
        if "role" in payload:
            role = _field_text(payload.get("role")).lower()
            roles = await service.store.role_map() if service.store.configured else DEFAULT_ROLES
            if role not in roles:
                raise HTTPException(status_code=400, detail="账号角色不存在")
            fields["role"] = role
        if "status" in payload:
            status = _field_text(payload.get("status")).lower()
            if status not in {"active", "disabled"}:
                raise HTTPException(status_code=400, detail="账号状态只能是 active 或 disabled")
            fields["status"] = status
        if "password" in payload:
            password = _field_text(payload.get("password"))
            if len(password) < 8:
                raise HTTPException(status_code=400, detail="密码至少需要 8 个字符")
            fields["password"] = password
        if "expires_at" in payload:
            try:
                expires_at = _expiry_timestamp(payload.get("expires_at"))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if expires_at <= time.time():
                raise HTTPException(status_code=400, detail="到期日期必须晚于当前时间")
            fields["expires_at"] = expires_at
        return service.local_accounts.update(account_id, fields)

    async def delete_local_account(request: Request, account_id: int):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以管理外部账号")
        if not service.local_accounts.delete(account_id):
            raise HTTPException(status_code=404, detail="账号不存在")
        return {"deleted": True}

    async def organization(request: Request, refresh: bool = False):
        user = await service.current_user(request)
        if not service.has_permission(user, "organization:view") and not service.has_permission(user, "organization:manage"):
            raise HTTPException(status_code=403, detail="没有查看组织与权限的权限")
        try:
            if refresh:
                service.store._cache_expires_at = 0
            return await service.organization(current_user=user, refresh=refresh)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def save_member(request: Request, open_id: str, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以修改成员授权")
        member = {**payload, "open_id": open_id}
        role_name = _field_text(member.get("role")).lower() or "member"
        status = _field_text(member.get("status")).lower() or "active"
        if status not in {"active", "disabled"}:
            raise HTTPException(status_code=400, detail="成员状态只能是 active 或 disabled")
        target_is_current_super_admin = bool(
            user.get("is_super_admin") and open_id in _identity_values(user)
        )
        if (service.is_super_admin(member) or target_is_current_super_admin) and (
            role_name != "admin" or status != "active"
        ):
            raise HTTPException(status_code=400, detail="默认超管不可停用或降级")
        try:
            if role_name not in await service.store.role_map():
                raise HTTPException(status_code=400, detail="成员角色不存在")
            result = await service.store.save_member({**member, "role": role_name, "status": status})
            service._organization_expires_at = 0
            return result
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def delete_member(request: Request, open_id: str):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以移除成员授权")
        if open_id in set(service.settings.super_admin_ids) or open_id in _identity_values(user):
            raise HTTPException(status_code=400, detail="默认超管不可移除授权")
        try:
            deleted = await service.store.delete_member({"open_id": open_id, "user_id": open_id})
            service._organization_expires_at = 0
            return {"deleted": deleted}
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def save_role(request: Request, role_name: str, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有超管可以修改角色")
        role_name = role_name.strip().lower()
        if not role_name or not role_name.replace("-", "").replace("_", "").isalnum():
            raise HTTPException(status_code=400, detail="角色标识只能包含字母、数字、下划线或连字符")
        try:
            result = await service.store.save_role({**payload, "name": role_name, "system": role_name in DEFAULT_ROLES})
            service._organization_expires_at = 0
            return result
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    app.add_api_route("/api/auth/config", auth_config, methods=["GET"])
    app.add_api_route("/api/auth/me", auth_me, methods=["GET"])
    app.add_api_route("/api/auth/local/login", local_login, methods=["POST"])
    app.add_api_route("/api/auth/feishu/login", auth_login, methods=["GET"])
    app.add_api_route("/auth/callback", auth_callback, methods=["GET"])
    app.add_api_route("/api/auth/feishu/callback", auth_callback, methods=["GET"])
    app.add_api_route("/api/auth/logout", auth_logout, methods=["GET", "POST"])
    app.add_api_route("/api/admin/local-accounts", local_accounts, methods=["GET"])
    app.add_api_route("/api/admin/local-accounts", create_local_account, methods=["POST"])
    app.add_api_route("/api/admin/local-accounts/{account_id}", update_local_account, methods=["PATCH"])
    app.add_api_route("/api/admin/local-accounts/{account_id}", delete_local_account, methods=["DELETE"])
    app.add_api_route("/api/admin/organization", organization, methods=["GET"])
    app.add_api_route("/api/admin/members/{open_id}", save_member, methods=["PUT"])
    app.add_api_route("/api/admin/members/{open_id}", delete_member, methods=["DELETE"])
    app.add_api_route("/api/admin/roles/{role_name}", save_role, methods=["PUT"])


PUBLIC_AUTH_PATHS = {
    "/api/auth/config",
    "/api/auth/me",
    "/api/auth/local/login",
    "/api/auth/feishu/login",
    "/auth/callback",
    "/api/auth/feishu/callback",
    "/api/auth/logout",
}

SENSITIVE_STATIC_PERMISSIONS = {
    "/static/api-settings.html": "menu:api-settings",
    "/static/comfyui-settings.html": "menu:workflow-settings",
    "/static/org-permissions.html": "menu:organization-permissions",
}
DISABLED_LOCAL_STATIC_PATHS = {
    "/static/zimage.html", "/static/enhance.html", "/static/klein.html", "/static/angle.html",
}
SUPER_ADMIN_UPDATE_PATHS = {
    "/api/check-update",
    "/api/update-connectivity",
    "/api/update-connectivity/probe",
    "/api/update-backups",
    "/api/update-from-github",
    "/api/update-rollback",
}


def _management_permission(path: str, method: str) -> str:
    if method in SAFE_METHODS:
        return ""
    if path.startswith(("/api/providers", "/api/config")):
        return "settings:api:manage"
    if path.startswith((
        "/api/storage-settings",
        "/api/update-from-github",
        "/api/update-rollback",
        "/api/comfyui/instances",
        "/api/workflows",
    )):
        return "settings:more:manage"
    return ""


async def auth_middleware(service: AuthService, request: Request, call_next):
    path = request.url.path
    method = request.method.upper()
    if path in PUBLIC_AUTH_PATHS or path == "/static/login.html" or path.startswith("/static/images/") or path.startswith("/static/vendor/"):
        return await call_next(request)
    if path in DISABLED_LOCAL_STATIC_PATHS:
        return RedirectResponse("/")
    try:
        user = await service.current_user(request)
    except FeishuAPIError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=502)
    if not user:
        if path == "/":
            return RedirectResponse("/static/login.html", status_code=302)
        if path.startswith("/api/"):
            return JSONResponse({"detail": "请使用飞书登录"}, status_code=401)
        if path.startswith("/static/") and path.endswith(".html"):
            return RedirectResponse("/static/login.html", status_code=302)
        return await call_next(request)
    static_permission = SENSITIVE_STATIC_PERMISSIONS.get(path)
    if static_permission and not service.has_permission(user, static_permission):
        return JSONResponse({"detail": "没有访问该页面的权限"}, status_code=403)
    if path in SUPER_ADMIN_UPDATE_PATHS and not user.get("is_super_admin"):
        return JSONResponse({"detail": "仅平台超管可查看或执行版本更新"}, status_code=403)
    required = _management_permission(path, method)
    if required and not service.has_permission(user, required):
        return JSONResponse({"detail": "没有修改设置的权限"}, status_code=403)
    if method not in SAFE_METHODS and path.startswith("/api/") and user.get("read_only") and path not in PUBLIC_AUTH_PATHS:
        return JSONResponse({"detail": "访客账号仅可查看，不能执行修改或生成操作"}, status_code=403)
    return await call_next(request)
