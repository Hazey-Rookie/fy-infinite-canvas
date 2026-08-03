import base64
import asyncio
from contextlib import closing
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, replace
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
TENANT_NAME_SYNC_INTERVAL_SECONDS = 5 * 60


def _auth_env_file() -> str:
    return os.getenv("FY_AUTH_CONFIG_FILE", "").strip() or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "API", ".env"
    )


def _persist_tenant_configs(tenants: Dict[str, Dict[str, Any]]) -> None:
    """Persist tenant SSO config in the private runtime env file atomically."""
    path = _auth_env_file()
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    existing: List[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8-sig") as handle:
            existing = handle.read().splitlines()
    value = json.dumps(list(tenants.values()), ensure_ascii=False, separators=(",", ":"))
    output: List[str] = []
    replaced = False
    for line in existing:
        if line.strip().startswith("FY_TENANTS_JSON="):
            output.append(f"FY_TENANTS_JSON={value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        if output and output[-1].strip():
            output.append("")
        output.append(f"FY_TENANTS_JSON={value}")
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(output).rstrip("\n") + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)

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

ROLE_PERMISSION_ALLOWLIST = set(DEFAULT_ROLES["admin"]["permissions"])
PLATFORM_ONLY_PERMISSIONS = {
    "menu:api-settings",
    "menu:more-settings",
    "menu:workflow-settings",
    "settings:api:manage",
    "settings:more:manage",
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
    cookie_secure: bool
    default_role: str
    tenants: Optional[Dict[str, Dict[str, Any]]] = None
    db_path: str = ""
    auth_db_path: str = ""
    local_auth_enabled: bool = True
    # Retained as compatibility-only fields; authorization always uses SQLite.
    bitable_app_token: str = ""
    members_table_id: str = ""
    roles_table_id: str = ""
    permission_store: str = "local"

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
        tenants: Dict[str, Dict[str, Any]] = {}
        raw_tenants = os.getenv("FY_TENANTS_JSON", "").strip()
        if raw_tenants:
            try:
                parsed = json.loads(raw_tenants)
                values = parsed.values() if isinstance(parsed, dict) else parsed
                for item in values:
                    if not isinstance(item, dict):
                        continue
                    key = _field_text(item.get("tenant_key") or item.get("key") or item.get("slug")).lower()
                    if key:
                        tenants[key] = {
                            "tenant_key": key,
                            "slug": _field_text(item.get("slug") or key).lower(),
                            "name": _field_text(item.get("name") or key),
                            "app_id": _field_text(item.get("app_id")),
                            "app_secret": _field_text(item.get("app_secret")),
                            "redirect_uris": list(dict.fromkeys(item.get("redirect_uris") or redirect_uris)),
                            "enabled": bool(item.get("enabled", True)),
                        }
            except (TypeError, ValueError, json.JSONDecodeError):
                tenants = {}
        default_tenant_key = os.getenv("FY_DEFAULT_TENANT_KEY", "default").strip().lower() or "default"
        default_tenant_name = os.getenv("FY_DEFAULT_TENANT_NAME", "默认企业").strip() or "默认企业"
        if not tenants:
            tenants[default_tenant_key] = {
                "tenant_key": default_tenant_key,
                "slug": default_tenant_key,
                "name": default_tenant_name,
                "app_id": app_id,
                "app_secret": app_secret,
                "redirect_uris": redirect_uris,
                "enabled": True,
            }
        return cls(
            app_id=app_id,
            app_secret=app_secret,
            redirect_uri=redirect_uris[0] if redirect_uris else "",
            redirect_uris=redirect_uris,
            session_secret=session_secret,
            super_admin_ids=_csv_env("FY_SUPER_ADMIN_IDS"),
            cookie_secure=_bool_env("FY_COOKIE_SECURE", False),
            default_role="member",
            tenants=tenants,
            db_path=os.getenv("FY_AUTH_DB_PATH", "").strip() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fy_auth.db"),
            auth_db_path=os.getenv("FY_AUTH_DB_PATH", "").strip(),
            local_auth_enabled=_bool_env("FY_LOCAL_AUTH_ENABLED", True),
            bitable_app_token=os.getenv("FEISHU_BITABLE_APP_TOKEN", "").strip(),
            members_table_id=os.getenv("FEISHU_BITABLE_MEMBERS_TABLE_ID", "").strip(),
            roles_table_id=os.getenv("FEISHU_BITABLE_ROLES_TABLE_ID", "").strip(),
            permission_store="local",
        )

    @property
    def allowed_redirect_uris(self) -> List[str]:
        return list(dict.fromkeys([item for item in [self.redirect_uri, *self.redirect_uris] if item]))

    @property
    def sso_configured(self) -> bool:
        if self.tenants is None:
            return bool(self.app_id and self.app_secret and self.allowed_redirect_uris and self.super_admin_ids)
        return any(
            item.get("app_id") and item.get("app_secret") and item.get("redirect_uris")
            for item in (self.tenants or {}).values()
        )

    @property
    def default_tenant_key(self) -> str:
        return next(iter(self.tenants or {}), "default")

    def tenant_config(self, tenant_key: str = "") -> Dict[str, Any]:
        key = _field_text(tenant_key).lower() or self.default_tenant_key
        if self.tenants is None or not self.tenants:
            return {
                "tenant_key": key, "slug": key, "name": "默认企业" if key == self.default_tenant_key else "当前企业",
                "app_id": self.app_id, "app_secret": self.app_secret,
                "redirect_uris": self.allowed_redirect_uris, "enabled": True,
            }
        return dict((self.tenants or {}).get(key) or {})

    def settings_for_tenant(self, tenant_key: str = "") -> "AuthSettings":
        config = self.tenant_config(tenant_key)
        return AuthSettings(
            app_id=_field_text(config.get("app_id") or self.app_id),
            app_secret=_field_text(config.get("app_secret") or self.app_secret),
            redirect_uri=_field_text((config.get("redirect_uris") or self.allowed_redirect_uris)[0] if (config.get("redirect_uris") or self.allowed_redirect_uris) else ""),
            redirect_uris=list(config.get("redirect_uris") or self.allowed_redirect_uris),
            session_secret=self.session_secret,
            super_admin_ids=self.super_admin_ids,
            cookie_secure=self.cookie_secure,
            default_role=self.default_role,
            tenants=self.tenants,
            db_path=self.db_path,
            auth_db_path=self.auth_db_path,
            local_auth_enabled=self.local_auth_enabled,
            bitable_app_token=self.bitable_app_token,
            members_table_id=self.members_table_id,
            roles_table_id=self.roles_table_id,
            permission_store="local",
        )

    def missing_sso_fields(self) -> List[str]:
        values = {
            "FEISHU_APP_ID": self.app_id,
            "FEISHU_APP_SECRET": self.app_secret,
            "FEISHU_REDIRECT_URIS": self.allowed_redirect_uris,
            "FY_SUPER_ADMIN_IDS": self.super_admin_ids,
        }
        return [key for key, value in values.items() if not value]

    def missing_bitable_fields(self) -> List[str]:
        return []


LOCAL_ACCOUNT_VALIDITY_DAYS = 30


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
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _b64decode(salt), int(iterations))
        return hmac.compare_digest(_b64encode(actual), expected)
    except (TypeError, ValueError):
        return False


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
    """Application-owned password accounts, explicitly scoped to a tenant."""

    def __init__(self, settings: AuthSettings):
        self.path = settings.db_path or settings.auth_db_path or os.getenv("FY_AUTH_DB_PATH", "").strip() or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fy_auth.db")
        self.default_tenant_key = settings.default_tenant_key
        self._memory_anchor: Optional[sqlite3.Connection] = None
        if self.path == ":memory:":
            self.path = f"file:fy-local-{secrets.token_hex(8)}?mode=memory&cache=shared"
            self._memory_anchor = sqlite3.connect(self.path, uri=True, check_same_thread=False)

    def _connect(self) -> sqlite3.Connection:
        is_memory_uri = self.path.startswith("file:")
        if not is_memory_uri:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False, uri=is_memory_uri)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not is_memory_uri:
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS local_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_key TEXT NOT NULL DEFAULT '',
            username TEXT NOT NULL COLLATE NOCASE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'guest',
            status TEXT NOT NULL DEFAULT 'active',
            expires_at REAL NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )""")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(local_accounts)").fetchall()}
        if "tenant_key" not in columns:
            conn.execute("ALTER TABLE local_accounts ADD COLUMN tenant_key TEXT NOT NULL DEFAULT ''")
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE local_accounts ADD COLUMN expires_at REAL")
            conn.execute("UPDATE local_accounts SET expires_at = ? WHERE expires_at IS NULL", (_expiry_timestamp(),))
        table_sql = str(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='local_accounts'").fetchone()[0] or "").upper()
        if "USERNAME TEXT NOT NULL COLLATE NOCASE UNIQUE" in table_sql:
            # Older FY builds enforced username uniqueness globally. Rebuild once so
            # the same external username can exist independently in each tenant.
            conn.execute("ALTER TABLE local_accounts RENAME TO local_accounts_legacy")
            conn.execute("""CREATE TABLE local_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_key TEXT NOT NULL DEFAULT '', username TEXT NOT NULL COLLATE NOCASE,
                display_name TEXT NOT NULL, password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'guest', status TEXT NOT NULL DEFAULT 'active',
                expires_at REAL NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
            )""")
            conn.execute("""INSERT INTO local_accounts
                (id, tenant_key, username, display_name, password_hash, role, status, expires_at, created_at, updated_at)
                SELECT id, tenant_key, username, display_name, password_hash, role, status,
                       COALESCE(expires_at, ?), created_at, updated_at
                FROM local_accounts_legacy""", (_expiry_timestamp(),))
            conn.execute("DROP TABLE local_accounts_legacy")
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(local_accounts)").fetchall()}
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_local_accounts_tenant_username ON local_accounts(tenant_key, username)")
        conn.execute("UPDATE local_accounts SET tenant_key = ? WHERE tenant_key = ''", (self.default_tenant_key,))
        conn.commit()
        return conn

    @staticmethod
    def _disable_expired(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE local_accounts SET status='disabled', updated_at=? WHERE status='active' AND expires_at <= ?", (time.time(), time.time()))
        conn.commit()

    @staticmethod
    def _row(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        result = dict(row)
        result.pop("password_hash", None)
        return result

    def get(self, account_id: int, tenant_key: str = "") -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            query, values = "SELECT * FROM local_accounts WHERE id = ?", [int(account_id)]
            if tenant_key:
                query += " AND tenant_key = ?"
                values.append(_field_text(tenant_key).lower())
            row = conn.execute(query, values).fetchone()
        return self._row(row)

    def authenticate(self, username: str, password: str, tenant_key: str = "") -> Optional[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            query, values = "SELECT * FROM local_accounts WHERE username = ?", [username.strip()]
            if tenant_key:
                query += " AND tenant_key = ?"
                values.append(_field_text(tenant_key).lower())
            rows = conn.execute(query, values).fetchall()
        if len(rows) != 1:
            return None
        row = rows[0]
        if row["status"] != "active" or not _password_matches(password, row["password_hash"]):
            return None
        return self._row(row)

    def create(self, username: str, display_name: str, password: str, role: str, tenant_key: str = "", expires_at: Any = None) -> Dict[str, Any]:
        now = time.time()
        with closing(self._connect()) as conn:
            target_tenant = _field_text(tenant_key).lower() or self.default_tenant_key
            cursor = conn.execute("INSERT INTO local_accounts (tenant_key, username, display_name, password_hash, role, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (target_tenant, username.strip(), display_name.strip(), _password_hash(password), role, _expiry_timestamp(expires_at), now, now))
            conn.commit()
            account_id = cursor.lastrowid
        return self.get(int(account_id), target_tenant) or {}

    def list(self, tenant_key: str = "") -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            self._disable_expired(conn)
            if tenant_key:
                rows = conn.execute("SELECT * FROM local_accounts WHERE tenant_key = ? ORDER BY id", (_field_text(tenant_key).lower(),)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM local_accounts ORDER BY tenant_key, id").fetchall()
        return [self._row(row) for row in rows if row is not None]

    def update(self, account_id: int, fields: Dict[str, Any], tenant_key: str = "") -> Optional[Dict[str, Any]]:
        allowed = {key: fields[key] for key in ("display_name", "role", "status", "expires_at") if key in fields}
        if "password" in fields and fields["password"]:
            allowed["password_hash"] = _password_hash(str(fields["password"]))
        if not allowed:
            return self.get(account_id, tenant_key)
        allowed["updated_at"] = time.time()
        assignments = ", ".join(f"{key} = ?" for key in allowed)
        values: List[Any] = list(allowed.values()) + [int(account_id)]
        query = f"UPDATE local_accounts SET {assignments} WHERE id = ?"
        if tenant_key:
            query += " AND tenant_key = ?"
            values.append(_field_text(tenant_key).lower())
        with closing(self._connect()) as conn:
            conn.execute(query, values)
            conn.commit()
        return self.get(account_id, tenant_key)

    def delete(self, account_id: int, tenant_key: str = "") -> bool:
        query, values = "DELETE FROM local_accounts WHERE id = ?", [int(account_id)]
        if tenant_key:
            query += " AND tenant_key = ?"
            values.append(_field_text(tenant_key).lower())
        with closing(self._connect()) as conn:
            cursor = conn.execute(query, values)
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
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                if response.is_error:
                    code = payload.get("code") if isinstance(payload, dict) else None
                    message = payload.get("msg") or payload.get("message") if isinstance(payload, dict) else ""
                    detail = message or f"HTTP {response.status_code}"
                    if code not in (None, ""):
                        detail = f"{detail}（code={code}）"
                    raise FeishuAPIError(f"飞书接口请求失败：{detail}")
        except FeishuAPIError:
            raise
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

    async def get_root_department(self) -> Dict[str, Any]:
        payload = await self._request(
            "GET",
            f"{FEISHU_OPEN_API}/contact/v3/departments/0",
            params={"department_id_type": "open_department_id", "user_id_type": "open_id"},
            headers=await self.tenant_headers(),
        )
        return dict((payload.get("data") or {}).get("department") or {})

    async def get_tenant_info(self) -> Dict[str, Any]:
        """Read the enterprise profile exposed by the tenant information API."""
        payload = await self._request(
            "GET",
            f"{FEISHU_OPEN_API}/tenant/v2/tenant/query",
            headers=await self.tenant_headers(),
        )
        data = payload.get("data") or {}
        tenant = data.get("tenant") if isinstance(data, dict) else data
        return dict(tenant or {}) if isinstance(tenant, dict) else {}

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


class SQLitePermissionStore:
    """Application-owned tenant-scoped authorization storage.

    Feishu remains the identity and directory source; this store owns roles,
    local overrides and tenant-admin assignments. Writes are transactional and
    use SQLite WAL so multiple workers do not silently overwrite each other.
    """

    def __init__(self, settings: AuthSettings, client: Optional[FeishuClient] = None):
        self.settings = settings
        self.client = client
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fy_auth.db")
        self.db_path = settings.db_path or settings.auth_db_path or os.getenv("FY_AUTH_DB_PATH", "") or default_path
        if not settings.db_path and not settings.auth_db_path and not os.getenv("FY_AUTH_DB_PATH") and settings.tenants is None:
            self.db_path = os.path.join(tempfile.gettempdir(), f"fy-auth-{secrets.token_hex(8)}.db")
        self._memory_anchor: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self.db_path = f"file:fy-auth-{secrets.token_hex(8)}?mode=memory&cache=shared"
            self._memory_anchor = sqlite3.connect(self.db_path, uri=True, check_same_thread=False)
        self._lock = threading.RLock()
        self._cache: Dict[str, Any] = {}
        self._cache_expires_at = 0.0
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        is_memory_uri = self.db_path.startswith("file:")
        if not is_memory_uri:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        connection = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False, uri=is_memory_uri)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if not is_memory_uri:
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    tenant_key TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS roles (
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    system INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (tenant_id, name),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS members (
                    tenant_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    open_id TEXT NOT NULL DEFAULT '',
                    user_id TEXT NOT NULL DEFAULT '',
                    union_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    mobile TEXT NOT NULL DEFAULT '',
                    department_ids TEXT NOT NULL DEFAULT '[]',
                    role_override TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    directory_state TEXT NOT NULL DEFAULT 'active',
                    is_tenant_admin INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (tenant_id, identity_key),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS departments (
                    tenant_id TEXT NOT NULL,
                    department_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    parent_department_id TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (tenant_id, department_id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS tenant_invitations (
                    token_hash TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL DEFAULT '',
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_members_lookup ON members(tenant_id, open_id, user_id, email, mobile);
                INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', '1');
                UPDATE schema_meta SET value = '3' WHERE key = 'version';
                """
            )
            for tenant_key, config in (self.settings.tenants or {}).items():
                self._ensure_tenant(connection, tenant_key, config.get("name") or tenant_key)
            connection.commit()

    @staticmethod
    def _now() -> int:
        return int(time.time() * 1000)

    def _ensure_tenant(self, connection: sqlite3.Connection, tenant_key: str, display_name: str = "") -> str:
        key = _field_text(tenant_key).lower() or "default"
        row = connection.execute("SELECT tenant_id, display_name FROM tenants WHERE tenant_key = ?", (key,)).fetchone()
        if row:
            configured_name = _field_text(display_name)
            if configured_name and (_field_text(row[1]) in {"", _field_text(row[0])}):
                connection.execute("UPDATE tenants SET display_name = ?, updated_at = ? WHERE tenant_id = ?", (configured_name, self._now(), row[0]))
            return str(row[0])
        tenant_id = secrets.token_hex(16)
        connection.execute(
            "INSERT INTO tenants(tenant_id, tenant_key, display_name, enabled, updated_at) VALUES (?, ?, ?, 1, ?)",
            (tenant_id, key, _field_text(display_name) or key, self._now()),
        )
        for name, role in DEFAULT_ROLES.items():
            connection.execute(
                "INSERT OR IGNORE INTO roles(tenant_id, name, display_name, permissions, system, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (tenant_id, name, role["display_name"], json.dumps(role["permissions"], ensure_ascii=False), int(role.get("system")), self._now()),
            )
        return tenant_id

    def tenant_id(self, tenant_key: str = "") -> str:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        with self._lock, self._connect() as connection:
            tenant_id = self._ensure_tenant(connection, key, (self.settings.tenant_config(key) or {}).get("name") or key)
            connection.commit()
            return tenant_id

    def tenant_enabled(self, tenant_key: str = "") -> bool:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        configured = self.settings.tenant_config(key)
        if configured and not bool(configured.get("enabled", True)):
            return False
        with self._lock, self._connect() as connection:
            row = connection.execute("SELECT enabled FROM tenants WHERE tenant_key = ?", (key,)).fetchone()
            return bool(row[0]) if row else bool((self.settings.tenant_config(key) or {}).get("enabled", False))

    def list_tenants(self) -> List[Dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute("SELECT tenant_id, tenant_key, display_name, enabled, updated_at FROM tenants ORDER BY tenant_key").fetchall()
        return [{"tenant_id": row["tenant_id"], "tenant_key": row["tenant_key"], "name": row["display_name"], "enabled": bool(row["enabled"]), "updated_at": row["updated_at"]} for row in rows]

    def set_tenant_enabled(self, tenant_key: str, enabled: bool, display_name: str = "") -> Dict[str, Any]:
        key = _field_text(tenant_key).lower()
        if not key:
            raise FeishuAPIError("租户标识不能为空")
        with self._lock, self._connect() as connection:
            tenant_id = self._ensure_tenant(connection, key, display_name or key)
            connection.execute("UPDATE tenants SET display_name = COALESCE(NULLIF(?, ''), display_name), enabled = ?, updated_at = ? WHERE tenant_id = ?", (_field_text(display_name), int(bool(enabled)), self._now(), tenant_id))
            connection.commit()
            row = connection.execute("SELECT tenant_id, tenant_key, display_name, enabled, updated_at FROM tenants WHERE tenant_id = ?", (tenant_id,)).fetchone()
        return {"tenant_id": row["tenant_id"], "tenant_key": row["tenant_key"], "name": row["display_name"], "enabled": bool(row["enabled"]), "updated_at": row["updated_at"]}

    def delete_tenant(self, tenant_key: str) -> bool:
        key = _field_text(tenant_key).lower()
        if not key:
            raise FeishuAPIError("租户标识不能为空")
        with self._lock, self._connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
            if count <= 1:
                raise FeishuAPIError("至少保留一个企业，不能解除最后一个企业")
            row = connection.execute("SELECT tenant_id FROM tenants WHERE tenant_key = ?", (key,)).fetchone()
            if not row:
                return False
            connection.execute("DELETE FROM tenants WHERE tenant_id = ?", (row[0],))
            connection.commit()
        self._cache.pop(key, None)
        self._cache_expires_at = 0
        return True

    @staticmethod
    def _invitation_hash(token: str) -> str:
        return hashlib.sha256(_field_text(token).encode("utf-8")).hexdigest()

    def create_tenant_invitation(self, tenant_name: str = "", ttl_seconds: int = 3600) -> Dict[str, Any]:
        ttl = max(300, min(int(ttl_seconds), 24 * 60 * 60))
        token = secrets.token_urlsafe(32)
        now = self._now()
        expires_at = now + ttl * 1000
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO tenant_invitations(token_hash, tenant_name, expires_at, used_at, created_at) VALUES (?, ?, ?, 0, ?)",
                (self._invitation_hash(token), _field_text(tenant_name), expires_at, now),
            )
            connection.commit()
        return {"token": token, "tenant_name": _field_text(tenant_name), "expires_at": expires_at}

    def tenant_invitation(self, token: str) -> Optional[Dict[str, Any]]:
        token_hash = self._invitation_hash(token)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT tenant_name, expires_at, used_at, created_at FROM tenant_invitations WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        if not row:
            return None
        now = self._now()
        return {
            "tenant_name": row["tenant_name"], "expires_at": row["expires_at"],
            "used": row["used_at"] != 0, "expired": row["expires_at"] <= now,
            "created_at": row["created_at"],
        }

    def claim_tenant_invitation(self, token: str) -> bool:
        token_hash = self._invitation_hash(token)
        now = self._now()
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tenant_invitations SET used_at = ? WHERE token_hash = ? AND used_at = 0 AND expires_at > ?",
                (-now, token_hash, now),
            )
            connection.commit()
        return cursor.rowcount == 1

    def finish_tenant_invitation(self, token: str, success: bool) -> None:
        token_hash = self._invitation_hash(token)
        with self._lock, self._connect() as connection:
            if success:
                connection.execute(
                    "UPDATE tenant_invitations SET used_at = ? WHERE token_hash = ? AND used_at < 0",
                    (self._now(), token_hash),
                )
            else:
                connection.execute(
                    "UPDATE tenant_invitations SET used_at = 0 WHERE token_hash = ? AND used_at < 0",
                    (token_hash,),
                )
            connection.commit()

    def _identity_key(self, user: Dict[str, Any]) -> str:
        return _field_text(user.get("open_id") or user.get("user_id") or user.get("union_id") or user.get("email") or user.get("mobile"))

    def _row_member(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "open_id": row["open_id"], "user_id": row["user_id"], "union_id": row["union_id"],
            "name": row["name"], "email": row["email"], "mobile": row["mobile"],
            "department_ids": _json_list(row["department_ids"]),
            "role": row["role_override"] or "", "status": row["status"],
            "directory_state": row["directory_state"],
            "is_tenant_admin": bool(row["is_tenant_admin"]),
            "updated_at": row["updated_at"], "managed": bool(row["role_override"] or row["is_tenant_admin"] or row["status"] != "active"),
        }

    async def snapshot(self, tenant_key: str = "", refresh: bool = False) -> Dict[str, Any]:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        if not refresh and self._cache.get(key) and time.time() < self._cache_expires_at:
            return self._cache[key]
        tenant_id = self.tenant_id(key)
        with self._lock, self._connect() as connection:
            role_rows = connection.execute("SELECT * FROM roles WHERE tenant_id = ? ORDER BY name", (tenant_id,)).fetchall()
            member_rows = connection.execute("SELECT * FROM members WHERE tenant_id = ? ORDER BY name", (tenant_id,)).fetchall()
        roles = {name: dict(role) for name, role in DEFAULT_ROLES.items()}
        for row in role_rows:
            roles[row["name"]] = {
                "name": row["name"], "display_name": row["display_name"],
                "permissions": _json_list(row["permissions"]), "system": bool(row["system"]),
                "updated_at": row["updated_at"],
            }
        result = {"members": [self._row_member(row) for row in member_rows], "roles": roles, "source": "local", "tenant_key": key}
        self._cache[key] = result
        self._cache_expires_at = time.time() + 15
        return result

    async def member_for(self, user: Dict[str, Any], tenant_key: str = "") -> Optional[Dict[str, Any]]:
        candidates = {_field_text(user.get(key)) for key in ("open_id", "user_id", "union_id", "email", "mobile")}
        candidates.discard("")
        if not candidates:
            return None
        snapshot = await self.snapshot(tenant_key)
        for member in snapshot["members"]:
            if candidates.intersection(_identity_values(member)):
                return member
        return None

    async def upsert_directory_user(self, user: Dict[str, Any], tenant_key: str = "", directory_state: str = "active") -> Dict[str, Any]:
        identity = self._identity_key(user)
        if not identity:
            return {}
        tenant_id = self.tenant_id(tenant_key)
        with self._lock, self._connect() as connection:
            existing = connection.execute("SELECT role_override, status, is_tenant_admin FROM members WHERE tenant_id = ? AND identity_key = ?", (tenant_id, identity)).fetchone()
            connection.execute(
                """INSERT INTO members(tenant_id, identity_key, open_id, user_id, union_id, name, email, mobile, department_ids, role_override, status, directory_state, is_tenant_admin, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, identity_key) DO UPDATE SET open_id=excluded.open_id, user_id=excluded.user_id, union_id=excluded.union_id, name=excluded.name, email=excluded.email, mobile=excluded.mobile, department_ids=excluded.department_ids, directory_state=excluded.directory_state, updated_at=excluded.updated_at""",
                (tenant_id, identity, _field_text(user.get("open_id")), _field_text(user.get("user_id")), _field_text(user.get("union_id")), _field_text(user.get("name")), _field_text(user.get("email")), _field_text(user.get("mobile")), json.dumps(user.get("department_ids") or [], ensure_ascii=False), (existing[0] if existing else None), (existing[1] if existing else "active"), directory_state, int(existing[2]) if existing else 0, self._now()),
            )
            connection.commit()
        self._cache_expires_at = 0
        return (await self.member_for(user, tenant_key)) or {}

    def directory_departments(self, tenant_key: str = "") -> List[Dict[str, Any]]:
        tenant_id = self.tenant_id(tenant_key)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT department_id, name, parent_department_id, updated_at FROM departments WHERE tenant_id = ? ORDER BY name, department_id",
                (tenant_id,),
            ).fetchall()
        return [
            {
                "open_department_id": row["department_id"],
                "name": row["name"],
                "parent_department_id": row["parent_department_id"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    async def sync_directory(
        self,
        users: List[Dict[str, Any]],
        tenant_key: str = "",
        departments: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        tenant_id = self.tenant_id(tenant_key)
        seen = set()
        with self._lock, self._connect() as connection:
            if departments is not None:
                connection.execute("DELETE FROM departments WHERE tenant_id = ?", (tenant_id,))
                for department in departments:
                    department_id = _field_text(department.get("open_department_id") or department.get("department_id"))
                    if not department_id:
                        continue
                    connection.execute(
                        "INSERT INTO departments(tenant_id, department_id, name, parent_department_id, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            tenant_id,
                            department_id,
                            _field_text(department.get("name")),
                            _field_text(department.get("parent_department_id") or department.get("parent_open_department_id")),
                            self._now(),
                        ),
                    )
            for user in users:
                identity = self._identity_key(user)
                if not identity:
                    continue
                seen.add(identity)
                existing = connection.execute("SELECT role_override, status, is_tenant_admin FROM members WHERE tenant_id = ? AND identity_key = ?", (tenant_id, identity)).fetchone()
                connection.execute(
                    """INSERT INTO members(tenant_id, identity_key, open_id, user_id, union_id, name, email, mobile, department_ids, role_override, status, directory_state, is_tenant_admin, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(tenant_id, identity_key) DO UPDATE SET open_id=excluded.open_id, user_id=excluded.user_id, union_id=excluded.union_id, name=excluded.name, email=excluded.email, mobile=excluded.mobile, department_ids=excluded.department_ids, directory_state='active', updated_at=excluded.updated_at""",
                    (tenant_id, identity, _field_text(user.get("open_id")), _field_text(user.get("user_id")), _field_text(user.get("union_id")), _field_text(user.get("name")), _field_text(user.get("email")), _field_text(user.get("mobile")), json.dumps(user.get("department_ids") or [], ensure_ascii=False), (existing[0] if existing else None), (existing[1] if existing else "active"), "active", int(existing[2]) if existing else 0, self._now()),
                )
            if seen:
                placeholders = ",".join("?" for _ in seen)
                connection.execute(f"UPDATE members SET directory_state = 'missing', updated_at = ? WHERE tenant_id = ? AND identity_key NOT IN ({placeholders})", (self._now(), tenant_id, *seen))
            connection.commit()
        self._cache_expires_at = 0

    async def save_member(self, member: Dict[str, Any], tenant_key: str = "") -> Dict[str, Any]:
        identity = self._identity_key(member)
        if not identity:
            raise FeishuAPIError("成员缺少稳定身份标识")
        tenant_id = self.tenant_id(tenant_key)
        role = _field_text(member.get("role")).lower() or self.settings.default_role
        status = _field_text(member.get("status")).lower() or "active"
        with self._lock, self._connect() as connection:
            existing = connection.execute("SELECT * FROM members WHERE tenant_id = ? AND identity_key = ?", (tenant_id, identity)).fetchone()
            connection.execute(
                """INSERT INTO members(tenant_id, identity_key, open_id, user_id, union_id, name, email, mobile, department_ids, role_override, status, directory_state, is_tenant_admin, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, identity_key) DO UPDATE SET open_id=excluded.open_id, user_id=excluded.user_id, union_id=excluded.union_id, name=excluded.name, email=excluded.email, mobile=excluded.mobile, department_ids=excluded.department_ids, role_override=excluded.role_override, status=excluded.status, is_tenant_admin=excluded.is_tenant_admin, updated_at=excluded.updated_at""",
                (tenant_id, identity, _field_text(member.get("open_id")), _field_text(member.get("user_id")), _field_text(member.get("union_id")), _field_text(member.get("name")), _field_text(member.get("email")), _field_text(member.get("mobile")), json.dumps(member.get("department_ids") or [], ensure_ascii=False), None if role == self.settings.default_role else role, status, _field_text(existing["directory_state"] if existing else "active") or "active", int(bool(member.get("is_tenant_admin", bool(existing and existing["is_tenant_admin"])))), self._now()),
            )
            connection.commit()
        self._cache_expires_at = 0
        return (await self.member_for(member, tenant_key)) or {}

    async def delete_member(self, member: Dict[str, Any], tenant_key: str = "") -> bool:
        identity = self._identity_key(member)
        tenant_id = self.tenant_id(tenant_key)
        with self._lock, self._connect() as connection:
            cursor = connection.execute("UPDATE members SET role_override = NULL, status = 'active', is_tenant_admin = 0, updated_at = ? WHERE tenant_id = ? AND identity_key = ?", (self._now(), tenant_id, identity))
            connection.commit()
        self._cache_expires_at = 0
        return cursor.rowcount > 0

    async def role_map(self, tenant_key: str = "") -> Dict[str, Dict[str, Any]]:
        return (await self.snapshot(tenant_key))["roles"]

    async def save_role(self, role: Dict[str, Any], tenant_key: str = "") -> Dict[str, Any]:
        name = _field_text(role.get("name")).lower()
        if not name:
            raise FeishuAPIError("角色标识不能为空")
        tenant_id = self.tenant_id(tenant_key)
        now = self._now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """INSERT INTO roles(tenant_id, name, display_name, permissions, system, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(tenant_id, name) DO UPDATE SET display_name=excluded.display_name, permissions=excluded.permissions, updated_at=excluded.updated_at""",
                (tenant_id, name, _field_text(role.get("display_name")) or name, json.dumps(_json_list(role.get("permissions")), ensure_ascii=False), int(name in DEFAULT_ROLES), now),
            )
            connection.commit()
        self._cache_expires_at = 0
        roles = await self.role_map(tenant_key)
        return roles.get(name) or {}

    async def delete_role(self, role_name: str, tenant_key: str = "") -> bool:
        name = _field_text(role_name).lower()
        if name in DEFAULT_ROLES:
            raise FeishuAPIError("内置角色不能删除")
        tenant_id = self.tenant_id(tenant_key)
        with self._lock, self._connect() as connection:
            refs = connection.execute("SELECT COUNT(*) FROM members WHERE tenant_id = ? AND role_override = ?", (tenant_id, name)).fetchone()[0]
            if refs:
                raise FeishuAPIError("角色仍被成员使用，请先重新分配成员")
            cursor = connection.execute("DELETE FROM roles WHERE tenant_id = ? AND name = ?", (tenant_id, name))
            connection.commit()
        self._cache_expires_at = 0
        return cursor.rowcount > 0


class AuthService:
    def __init__(self, settings: Optional[AuthSettings] = None):
        self.settings = settings or AuthSettings.from_env()
        self.codec = SignedTokenCodec(self.settings.session_secret)
        self._clients: Dict[str, FeishuClient] = {}
        self.feishu = self.feishu_for(self.settings.default_tenant_key)
        self.store = SQLitePermissionStore(self.settings, self.feishu)
        self.local_accounts = LocalAccountStore(self.settings)
        self._local_login_failures: Dict[str, List[float]] = {}
        self._organization_cache: Dict[str, Dict[str, Any]] = {}
        self._organization_expires_at: Dict[str, float] = {}
        self._department_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._department_expires_at: Dict[str, float] = {}
        self._tenant_name_expires_at: Dict[str, float] = {}

    def feishu_for(self, tenant_key: str = "") -> FeishuClient:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        if self.settings.tenants is None and self._clients and key not in self._clients:
            return next(iter(self._clients.values()))
        if key not in self._clients:
            self._clients[key] = FeishuClient(self.settings.settings_for_tenant(key))
        return self._clients[key]

    def tenant_config(self, tenant_key: str = "") -> Dict[str, Any]:
        return self.settings.tenant_config(tenant_key)

    def tenant_exists(self, tenant_key: str = "") -> bool:
        key = _field_text(tenant_key).lower()
        if not key:
            return False
        return key == self.settings.default_tenant_key or any(item.get("tenant_key") == key for item in self.list_tenants())

    def tenant_key_for_identifier(self, identifier: str = "") -> str:
        value = _field_text(identifier).lower()
        if not value:
            return ""
        for tenant in self.list_tenants():
            if value in {_field_text(tenant.get("tenant_key")).lower(), _field_text(tenant.get("slug")).lower()}:
                return _field_text(tenant.get("tenant_key")).lower()
        return ""

    def list_tenants(self) -> List[Dict[str, Any]]:
        stored = {item["tenant_key"]: item for item in self.store.list_tenants()}
        configured = self.settings.tenants
        # A tenant must have persisted application credentials to be usable. Database
        # rows left by an interrupted onboarding flow are intentionally not exposed.
        if configured is None:
            configured = {}
            keys = list(dict.fromkeys([self.settings.default_tenant_key, *stored.keys()]))
        else:
            keys = list(configured.keys())
        if not keys:
            keys = [self.settings.default_tenant_key]
        result = []
        for key in keys:
            config = dict(configured.get(key) or {})
            item = dict(stored.get(key) or {})
            stored_name = _field_text(item.get("name"))
            configured_name = _field_text(config.get("name"))
            display_name = stored_name if stored_name and stored_name not in {key, _field_text(item.get("tenant_id"))} else (configured_name or key)
            result.append({
                "tenant_id": item.get("tenant_id") or self.store.tenant_id(key),
                "tenant_key": key,
                "slug": config.get("slug") or key,
                "name": display_name,
                "enabled": bool(item.get("enabled", config.get("enabled", True))),
                "app_id": _field_text(config.get("app_id")),
                "credential_configured": bool(config.get("app_id") and config.get("app_secret") and config.get("redirect_uris")),
                "redirect_uris": list(config.get("redirect_uris") or []),
            })
        return result

    def save_tenant(self, payload: Dict[str, Any], tenant_key: str = "") -> Dict[str, Any]:
        key = _field_text(payload.get("tenant_key") or tenant_key).lower()
        if not key or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", key):
            raise FeishuAPIError("租户标识只能包含小写字母、数字、下划线或连字符")
        tenants = {name: dict(config) for name, config in (self.settings.tenants or {}).items()}
        existing = dict(tenants.get(key) or self.settings.tenant_config(key) or {})
        app_id = _field_text(payload.get("app_id")) or _field_text(existing.get("app_id"))
        app_secret = _field_text(payload.get("app_secret")) or _field_text(existing.get("app_secret"))
        redirects = payload.get("redirect_uris")
        if redirects is None:
            redirects = existing.get("redirect_uris") or self.settings.allowed_redirect_uris
        redirects = list(dict.fromkeys(_field_text(item) for item in (redirects or []) if _field_text(item)))
        if not app_id or not app_secret or not redirects:
            raise FeishuAPIError("企业认证需要 app_id、app_secret 和至少一个回调地址")
        config = {
            "tenant_key": key,
            "slug": _field_text(payload.get("slug") or existing.get("slug") or key).lower(),
            "name": _field_text(payload.get("name") or existing.get("name") or key),
            "app_id": app_id,
            "app_secret": app_secret,
            "redirect_uris": redirects,
            "enabled": bool(payload.get("enabled", existing.get("enabled", True))),
        }
        tenants[key] = config
        _persist_tenant_configs(tenants)
        self.settings = replace(self.settings, tenants=tenants)
        self.store.settings = self.settings
        self._clients.pop(key, None)
        self._tenant_name_expires_at.pop(key, None)
        self.store.set_tenant_enabled(key, config["enabled"], config["name"])
        if key == self.settings.default_tenant_key:
            self.feishu = self.feishu_for(key)
        return next(item for item in self.list_tenants() if item["tenant_key"] == key)

    def remove_tenant(self, tenant_key: str) -> bool:
        key = _field_text(tenant_key).lower()
        if not key or not self.tenant_exists(key):
            raise FeishuAPIError("企业不存在")
        tenants = {name: dict(config) for name, config in (self.settings.tenants or {}).items()}
        if len(self.list_tenants()) <= 1:
            raise FeishuAPIError("至少保留一个企业，不能解除最后一个企业")
        deleted = self.store.delete_tenant(key)
        if not deleted:
            raise FeishuAPIError("企业不存在")
        tenants.pop(key, None)
        if not tenants:
            raise FeishuAPIError("至少保留一个企业，不能解除最后一个企业")
        _persist_tenant_configs(tenants)
        self.settings = replace(self.settings, tenants=tenants)
        self.store.settings = self.settings
        self._clients.pop(key, None)
        self._tenant_name_expires_at.pop(key, None)
        self._organization_cache.pop(key, None)
        self._organization_expires_at.pop(key, None)
        return True

    def is_tenant_enabled(self, tenant_key: str = "") -> bool:
        return self.store.tenant_enabled(tenant_key)

    def tenant_summary(self, tenant_key: str = "") -> Dict[str, Any]:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        stored = next((item for item in self.store.list_tenants() if item.get("tenant_key") == key), {})
        configured = self.tenant_config(key)
        stored_name = _field_text(stored.get("name"))
        configured_name = _field_text(configured.get("name"))
        identifier_names = {key, _field_text(stored.get("tenant_id")), _field_text(configured.get("tenant_key"))}
        looks_like_internal_id = bool(stored_name and (stored_name in identifier_names or re.fullmatch(r"[a-f0-9]{12,}", stored_name)))
        if not stored_name or looks_like_internal_id:
            stored_name = configured_name if configured_name and configured_name not in identifier_names else ""
        if not stored_name:
            stored_name = "默认企业" if key == self.settings.default_tenant_key else "当前企业"
        return {
            "tenant_key": key,
            "name": stored_name,
            "enabled": self.is_tenant_enabled(key),
        }

    async def sync_tenant_profile(self, tenant_key: str = "", force: bool = False, strict: bool = False) -> Dict[str, Any]:
        summary = self.tenant_summary(tenant_key)
        key = summary["tenant_key"]
        config = self.tenant_config(key)
        if not _field_text(config.get("app_id")) or not _field_text(config.get("app_secret")):
            if strict:
                raise FeishuAPIError("企业尚未配置飞书应用凭据")
            return summary
        now = time.time()
        if not force and now < self._tenant_name_expires_at.get(key, 0):
            return summary
        try:
            tenant = await self.feishu_for(key).get_tenant_info()
            name = _field_text(tenant.get("name") or tenant.get("tenant_name"))
            if not name:
                raise FeishuAPIError("飞书企业信息接口未返回企业名称")
            self.store.set_tenant_enabled(key, summary["enabled"], name)
            summary["name"] = name
            self._tenant_name_expires_at[key] = now + TENANT_NAME_SYNC_INTERVAL_SECONDS
        except FeishuAPIError as exc:
            self._tenant_name_expires_at[key] = now + 60
            if strict:
                raise FeishuAPIError(
                    f"同步企业信息失败，请确认飞书应用已开通 tenant:tenant:readonly：{exc}"
                ) from exc
        return summary

    async def sync_all_tenant_profiles(self, force: bool = False) -> List[Dict[str, Any]]:
        await asyncio.gather(*(
            self.sync_tenant_profile(item["tenant_key"], force=force)
            for item in self.list_tenants()
        ), return_exceptions=True)
        return self.list_tenants()

    async def department_names_for_user(self, user: Dict[str, Any]) -> List[str]:
        existing = [_field_text(item) for item in _json_list(user.get("department_names"))]
        existing = [item for item in existing if item]
        if existing:
            return existing
        department_ids = [_field_text(item) for item in _json_list(user.get("department_ids"))]
        department_ids = [item for item in department_ids if item]
        if not department_ids:
            return []
        tenant_key = _field_text(user.get("tenant_key")).lower() or self.settings.default_tenant_key
        if not self._department_cache.get(tenant_key) or time.time() >= self._department_expires_at.get(tenant_key, 0):
            self._department_cache[tenant_key] = self.store.directory_departments(tenant_key)
            self._department_expires_at[tenant_key] = time.time() + 300
        names_by_id = {
            _field_text(item.get("open_department_id") or item.get("department_id")): _field_text(item.get("name"))
            for item in self._department_cache.get(tenant_key, [])
        }
        return list(dict.fromkeys(names_by_id.get(item, "") for item in department_ids if names_by_id.get(item)))

    def is_super_admin(self, user: Dict[str, Any], tenant_key: str = "") -> bool:
        tenant = _field_text(tenant_key or user.get("tenant_key")).lower() or self.settings.default_tenant_key
        identities = _identity_values(user)
        for raw in self.settings.super_admin_ids:
            item = _field_text(raw)
            if ":" in item:
                expected_tenant, expected_identity = item.split(":", 1)
                if expected_tenant.lower() == tenant and expected_identity in identities:
                    return True
            elif item in identities:
                return True
        return False

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
        tenant_key = _field_text(profile.get("tenant_key")).lower() or self.settings.default_tenant_key
        profile["tenant_key"] = tenant_key
        super_admin = self.is_super_admin(profile, tenant_key)
        member = None if local_account else await self.store.member_for(profile, tenant_key)
        if member:
            for field in ("department_ids", "name", "email", "mobile", "avatar_url"):
                value = member.get(field)
                if value and not profile.get(field):
                    profile[field] = value
        role_name = "admin" if super_admin else _field_text((member or {}).get("role") or profile.get("role") or self.settings.default_role).lower()
        roles = await self.store.role_map(tenant_key)
        role = roles.get(role_name) or roles.get(self.settings.default_role) or DEFAULT_ROLES["member"]
        permissions = list(role.get("permissions") or [])
        tenant_admin = not super_admin and role_name == "admin"
        if super_admin:
            permissions = sorted({permission for item in roles.values() for permission in item.get("permissions") or []})
            permissions.extend(["organization:manage", "roles:manage", "tenants:manage"])
        elif tenant_admin:
            permissions.extend([
                "menu:organization-permissions",
                "organization:view",
                "organization:manage",
            ])
        if not super_admin:
            permissions = [permission for permission in permissions if permission not in {"settings:api:manage", "settings:more:manage", "tenants:manage", "menu:api-settings", "menu:more-settings", "menu:workflow-settings"}]
        status = "active" if super_admin else (local_account or member or {}).get("status") or "active"
        if not self.is_tenant_enabled(tenant_key):
            status = "disabled"
        profile.update({
            "tenant_id": self.store.tenant_id(tenant_key),
            "role": role_name,
            "permissions": sorted(set(permissions)),
            "is_super_admin": super_admin,
            "is_tenant_admin": tenant_admin,
            "read_only": role_name == "guest" or "action:write" not in permissions,
            "status": status,
        })
        return profile

    async def authenticate_local(self, username: str, password: str, tenant_key: str = "") -> Optional[Dict[str, Any]]:
        if not self.settings.local_auth_enabled:
            return None
        key = f"{_field_text(tenant_key).lower()}:{username.strip().casefold()}"
        now = time.time()
        recent = [item for item in self._local_login_failures.get(key, []) if now - item < 600]
        if len(recent) >= 5:
            self._local_login_failures[key] = recent
            return None
        account = self.local_accounts.authenticate(username, password, tenant_key)
        if not account:
            recent.append(now)
            self._local_login_failures[key] = recent[-5:]
            return None
        self._local_login_failures.pop(key, None)
        return await self.resolve_profile({"auth_type": "local", "local_account_id": account["id"], "tenant_key": account["tenant_key"]})

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
        if payload.get("tenant_key") and not stored_user.get("tenant_key"):
            stored_user["tenant_key"] = payload.get("tenant_key")
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
        tenants = self.list_tenants()
        return {
            "sso_enabled": True,
            "sso_configured": self.settings.sso_configured,
            "local_auth_enabled": self.settings.local_auth_enabled,
            "permission_store": "local",
            "missing_sso_fields": self.settings.missing_sso_fields(),
            "default_role": self.settings.default_role,
            "default_tenant_key": self.settings.default_tenant_key,
            "tenants": [
                {
                    "tenant_key": item["tenant_key"],
                    "slug": item.get("slug") or item["tenant_key"],
                    "name": item.get("name") or item["tenant_key"],
                    "enabled": item["enabled"],
                }
                for item in tenants
            ],
        }

    def redirect_uri_for_request(self, request: Request, tenant_key: str = "") -> str:
        allowed = self.settings.settings_for_tenant(tenant_key).allowed_redirect_uris
        if not allowed:
            return ""
        request_origin = f"{request.url.scheme}://{request.url.netloc}".lower()
        for candidate in allowed:
            parsed = urllib.parse.urlsplit(candidate)
            candidate_origin = f"{parsed.scheme}://{parsed.netloc}".lower()
            if candidate_origin == request_origin:
                return candidate
        return allowed[0]

    async def sync_directory(self, tenant_key: str = "", allow_unregistered: bool = False) -> Dict[str, Any]:
        key = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        if not allow_unregistered and not self.tenant_exists(key):
            raise FeishuAPIError("企业不存在")
        if not self.is_tenant_enabled(key):
            raise FeishuAPIError("企业已停用，不能同步成员")
        client = self.feishu_for(key)
        root_department = await client.get_root_department()
        root_name = _field_text(root_department.get("name"))
        departments = await client.list_departments()
        if root_name:
            root_department = {**root_department, "open_department_id": _field_text(root_department.get("open_department_id")) or "0", "name": root_name}
            departments = [root_department, *[item for item in departments if _field_text(item.get("open_department_id") or item.get("department_id")) != "0"]]
        self._department_cache[key] = departments
        self._department_expires_at[key] = time.time() + 300
        department_ids = [
            _field_text(item.get("open_department_id") or item.get("department_id"))
            for item in departments
        ]
        department_ids = [item for item in department_ids if item]
        users_by_id: Dict[str, Dict[str, Any]] = {}
        semaphore = asyncio.Semaphore(5)

        async def load_department_users(department_id: str):
            async with semaphore:
                users = await client.list_users_for_department(department_id)
                return department_id, users

        unique_department_ids = list(dict.fromkeys(["0", *department_ids]))
        user_groups = await asyncio.gather(*(load_department_users(item) for item in unique_department_ids))
        for department_id, users_in_department in user_groups:
            for directory_user in users_in_department:
                key_value = _field_text(directory_user.get("open_id") or directory_user.get("user_id"))
                if not key_value:
                    continue
                existing = users_by_id.get(key_value) or {}
                merged = {**existing, **directory_user}
                memberships = [*_json_list(existing.get("department_ids")), *_json_list(directory_user.get("department_ids"))]
                if department_id != "0":
                    memberships.append(department_id)
                merged["department_ids"] = list(dict.fromkeys(item for item in memberships if item))
                users_by_id[key_value] = merged
        directory_users = list(users_by_id.values())
        await self.store.sync_directory(directory_users, key, departments=departments)
        self._organization_cache[key] = {"departments": departments, "directory_users": directory_users}
        self._organization_expires_at[key] = time.time() + 60
        return {"tenant_key": key, "departments": departments, "users": directory_users, "synced_at": int(time.time() * 1000)}

    async def verify_tenant_connection(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        app_id = _field_text(payload.get("app_id"))
        app_secret = _field_text(payload.get("app_secret"))
        redirects = list(dict.fromkeys(_field_text(item) for item in (payload.get("redirect_uris") or []) if _field_text(item)))
        if not app_id or not app_secret or not redirects:
            raise FeishuAPIError("企业认证需要 App ID、App Secret 和至少一个回调地址")
        candidate = AuthSettings(
            app_id=app_id, app_secret=app_secret, redirect_uri=redirects[0], redirect_uris=redirects,
            session_secret=self.settings.session_secret, super_admin_ids=self.settings.super_admin_ids,
            cookie_secure=self.settings.cookie_secure, default_role=self.settings.default_role,
            tenants=None, db_path=self.settings.db_path,
        )
        client = FeishuClient(candidate)
        enterprise_name = ""
        invitation_name = _field_text(payload.get("tenant_name"))
        tenant_error: Optional[Exception] = None
        try:
            tenant = await client.get_tenant_info()
            enterprise_name = _field_text(tenant.get("name") or tenant.get("tenant_name"))
        except FeishuAPIError as exc:
            tenant_error = exc
        if not enterprise_name:
            try:
                root = await client.get_root_department()
                enterprise_name = _field_text(root.get("name"))
            except FeishuAPIError as exc:
                tenant_error = exc
        if not enterprise_name:
            # Some test tenants return 404 for tenant/v2/tenant and hide the
            # root department name. A successful directory read still proves
            # the app is authorized; use the invitation label until sync can
            # replace it with the real Feishu root department name.
            try:
                await client.list_departments()
                enterprise_name = invitation_name
            except FeishuAPIError as exc:
                tenant_error = exc
        if not enterprise_name:
            detail = "已验证飞书应用身份，但读取企业名称失败。请确认已开通 tenant:tenant:readonly 或通讯录读取权限，并确认应用已发布、已授权当前企业后重试"
            if tenant_error:
                detail = f"{detail}（飞书接口：{tenant_error}）"
            raise FeishuAPIError(detail)
        return {"verified": True, "enterprise_name": enterprise_name}

    async def organization(self, current_user: Optional[Dict[str, Any]] = None, refresh: bool = False) -> Dict[str, Any]:
        tenant_key = _field_text((current_user or {}).get("tenant_key")).lower() or self.settings.default_tenant_key
        if refresh:
            await self.sync_directory(tenant_key, allow_unregistered=True)

        cache_is_current = time.time() < self._organization_expires_at.get(tenant_key, 0)
        organization_cache = (self._organization_cache.get(tenant_key) or {}) if cache_is_current else {}
        snapshot = await self.store.snapshot(tenant_key)
        departments = organization_cache.get("departments") or self.store.directory_departments(tenant_key)
        directory_users = list(organization_cache.get("directory_users") or [
            item for item in snapshot["members"] if item.get("directory_state") != "missing"
        ])
        current_ids = _identity_values(current_user)
        if current_user and current_ids and not any(current_ids.intersection(_identity_values(item)) for item in directory_users):
            directory_users.append(current_user)
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
            is_super_admin = self.is_super_admin(item, tenant_key)
            role_name = "admin" if is_super_admin else assignment.get("role") or "member"
            users.append({
                "open_id": _field_text(item.get("open_id")),
                "user_id": _field_text(item.get("user_id")),
                "name": _field_text(item.get("name")),
                "email": _field_text(item.get("email")),
                "mobile": _field_text(item.get("mobile")),
                "department_ids": item.get("department_ids") or [],
                "role": role_name,
                "status": "active" if is_super_admin else assignment.get("status") or "active",
                "is_current": is_current,
                "is_super_admin": is_super_admin,
                "is_tenant_admin": not is_super_admin and role_name == "admin",
                "managed": bool(
                    assignment.get("managed")
                    or assignment.get("role")
                    or assignment.get("is_tenant_admin")
                    or assignment.get("status") == "disabled"
                ),
            })
        result = {
            "departments": departments,
            "users": users,
            "roles": list(snapshot["roles"].values()),
            "source": snapshot["source"],
            "tenant_key": tenant_key,
            "tenant": self.tenant_summary(tenant_key),
        }
        return result

    def can_manage_organization(self, user: Optional[Dict[str, Any]], tenant_key: str = "") -> bool:
        if not user:
            return False
        target = _field_text(tenant_key).lower() or self.settings.default_tenant_key
        return self.is_super_admin(user, target) or (
            bool(user.get("is_tenant_admin")) and _field_text(user.get("tenant_key")).lower() == target
        )


def _return_path(value: str) -> str:
    text = str(value or "/").strip()
    if not text.startswith("/") or text.startswith("//"):
        return "/"
    return text


def _url_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def register_auth(app, service: AuthService) -> None:
    def is_trusted_return_origin(origin: str) -> bool:
        normalized = _url_origin(origin)
        if not normalized:
            return False
        configured_origins = {
            _url_origin(uri)
            for tenant in (service.settings.tenants or {}).values()
            for uri in (tenant.get("redirect_uris") or [])
        }
        if normalized in configured_origins:
            return True
        parsed = urllib.parse.urlsplit(normalized)
        return (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed.port in {3000, 8000}
        )

    async def auth_config():
        return service.public_config()

    async def auth_me(request: Request):
        user = await service.current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="请使用飞书登录")
        public_user = dict(user)
        public_user["department_names"] = await service.department_names_for_user(public_user)
        tenant = service.tenant_summary(public_user.get("tenant_key"))
        return {
            "user": public_user,
            "tenant": tenant,
            "config": service.public_config(),
        }

    async def local_login(request: Request, payload: Dict[str, Any] = Body(...)):
        if not service.settings.local_auth_enabled:
            raise HTTPException(status_code=404, detail="本地账号登录未启用")
        username = _field_text(payload.get("username"))
        password = _field_text(payload.get("password"))
        tenant_key = _field_text(payload.get("tenant_key") or payload.get("tenant") or service.settings.default_tenant_key).lower()
        if not username or not password:
            raise HTTPException(status_code=400, detail="请输入账号和密码")
        if not service.tenant_exists(tenant_key) or not service.is_tenant_enabled(tenant_key):
            raise HTTPException(status_code=401, detail="账号或密码错误，或企业已停用")
        user = await service.authenticate_local(username, password, tenant_key)
        if not user:
            raise HTTPException(status_code=401, detail="账号或密码错误，或账号已停用")
        session = service.codec.encode({
            "kind": "session", "auth_type": "local", "local_account_id": user["id"],
            "tenant_key": user["tenant_key"],
        }, 12 * 60 * 60)
        response = JSONResponse({"ok": True, "return_to": _return_path(payload.get("return_to") or "/")})
        response.set_cookie(SESSION_COOKIE, session, max_age=12 * 60 * 60, httponly=True, secure=service.settings.cookie_secure, samesite="lax")
        return response

    async def auth_login(request: Request, return_to: str = "/", tenant_slug: str = ""):
        tenant_identifier = _field_text(tenant_slug or request.query_params.get("tenant") or service.settings.default_tenant_key).lower()
        tenant_key = service.tenant_key_for_identifier(tenant_identifier) or tenant_identifier
        config = service.tenant_config(tenant_key)
        if not service.tenant_exists(tenant_key) or not config or not config.get("enabled", True):
            raise HTTPException(status_code=404, detail="企业租户不存在或已停用")
        if not service.settings.sso_configured or not config.get("app_id") or not config.get("app_secret"):
            raise HTTPException(status_code=503, detail="飞书 SSO 缺少必要配置")
        redirect_uri = service.redirect_uri_for_request(request, tenant_key)
        nonce = secrets.token_urlsafe(24)
        state = service.codec.encode({
            "kind": "oauth",
            "nonce": nonce,
            "return_to": _return_path(return_to),
            "return_origin": _url_origin(str(request.base_url)) if is_trusted_return_origin(str(request.base_url)) else "",
            "redirect_uri": redirect_uri,
            "tenant_key": tenant_key,
        }, 600)
        response = RedirectResponse(service.feishu_for(tenant_key).authorize_url(state, redirect_uri), status_code=302)
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
        tenant_key = _field_text(state_payload.get("tenant_key")).lower() or service.settings.default_tenant_key
        config = service.tenant_config(tenant_key)
        if not config or not config.get("enabled", True):
            raise HTTPException(status_code=404, detail="企业租户不存在或已停用")
        redirect_uri = _field_text(state_payload.get("redirect_uri"))
        if redirect_uri not in service.settings.settings_for_tenant(tenant_key).allowed_redirect_uris:
            raise HTTPException(status_code=400, detail="飞书登录回调地址无效，请重新登录")
        try:
            client = service.feishu_for(tenant_key)
            user = await client.exchange_code(code, redirect_uri)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        try:
            user = await client.get_user(user)
        except FeishuAPIError:
            # OAuth already supplied a verified identity. Contact permissions are
            # optional for sign-in and only enrich the profile/organization view.
            pass
        # Feishu's tenant_key is an external tenant identifier. It is not the
        # platform's internal tenant slug (for example, "test"), so comparing
        # the two would reject valid cross-tenant app logins. The OAuth code
        # was exchanged with this tenant's own App ID/Secret, which binds the
        # identity to the target app configuration.
        user = {**user, "tenant_key": tenant_key}
        await service.store.upsert_directory_user(user, tenant_key)
        session = service.codec.encode({"kind": "session", "tenant_key": tenant_key, "user": user}, 12 * 60 * 60)
        return_path = _return_path(state_payload.get("return_to") or "/")
        return_origin = _url_origin(state_payload.get("return_origin"))
        redirect_target = f"{return_origin}{return_path}" if is_trusted_return_origin(return_origin) else return_path
        response = RedirectResponse(redirect_target, status_code=302)
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
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
        return response

    def requested_tenant(user: Optional[Dict[str, Any]], requested: str = "") -> str:
        current = _field_text(user.get("tenant_key") if user else "").lower() or service.settings.default_tenant_key
        target = _field_text(requested).lower() or current
        if not requested and user and user.get("is_super_admin") and not service.tenant_exists(target):
            target = service.settings.default_tenant_key
        if target != current and not (user and user.get("is_super_admin")):
            raise HTTPException(status_code=403, detail="只有平台超管可以切换企业")
        if not service.tenant_exists(target):
            raise HTTPException(status_code=404, detail="企业不存在")
        return target

    async def local_accounts(request: Request, tenant_key: str = ""):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理外部账号")
        target = requested_tenant(user, tenant_key)
        return {"tenant_key": target, "accounts": service.local_accounts.list(target)}

    async def create_local_account(request: Request, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理外部账号")
        target = requested_tenant(user, _field_text(payload.get("tenant_key") or payload.get("tenant")))
        username = _field_text(payload.get("username"))
        display_name = _field_text(payload.get("display_name") or payload.get("name"))
        password = _field_text(payload.get("password"))
        role = _field_text(payload.get("role") or "guest").lower()
        if len(username) < 3 or len(username) > 64 or not all(char.isalnum() or char in "._-@+" for char in username):
            raise HTTPException(status_code=400, detail="账号格式无效")
        if not display_name or len(display_name) > 80:
            raise HTTPException(status_code=400, detail="请填写展示名称")
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="密码至少需要 8 个字符")
        try:
            expires_at = _expiry_timestamp(payload.get("expires_at"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if expires_at <= time.time():
            raise HTTPException(status_code=400, detail="到期日期必须晚于当前时间")
        if role not in await service.store.role_map(target):
            raise HTTPException(status_code=400, detail="账号角色不存在")
        try:
            return service.local_accounts.create(username, display_name, password, role, target, expires_at)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="该租户下账号已存在") from exc

    async def update_local_account(request: Request, account_id: int, payload: Dict[str, Any] = Body(...), tenant_key: str = ""):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理外部账号")
        target = requested_tenant(user, _field_text(payload.get("tenant_key") or tenant_key))
        existing = service.local_accounts.get(account_id, target)
        if not existing:
            raise HTTPException(status_code=404, detail="账号不存在")
        fields: Dict[str, Any] = {}
        if "display_name" in payload:
            value = _field_text(payload.get("display_name"))
            if not value or len(value) > 80:
                raise HTTPException(status_code=400, detail="展示名称无效")
            fields["display_name"] = value
        if "role" in payload:
            role = _field_text(payload.get("role")).lower()
            if role not in await service.store.role_map(target):
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
        return service.local_accounts.update(account_id, fields, target)

    async def delete_local_account(request: Request, account_id: int, tenant_key: str = ""):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理外部账号")
        target = requested_tenant(user, tenant_key)
        if not service.local_accounts.delete(account_id, target):
            raise HTTPException(status_code=404, detail="账号不存在")
        return {"deleted": True}

    async def organization(request: Request, refresh: bool = False, tenant_key: str = ""):
        user = await service.current_user(request)
        target = requested_tenant(user, tenant_key)
        if not (user and user.get("is_super_admin")) and not service.has_permission(user, "organization:view") and not service.has_permission(user, "organization:manage"):
            raise HTTPException(status_code=403, detail="没有查看组织与权限的权限")
        try:
            if refresh:
                service.store._cache_expires_at = 0
            scoped_user = {**(user or {}), "tenant_key": target}
            return await service.organization(current_user=scoped_user, refresh=refresh)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def save_member(request: Request, open_id: str, payload: Dict[str, Any] = Body(...), tenant_key: str = ""):
        user = await service.current_user(request)
        tenant_key = requested_tenant(user, tenant_key)
        if not service.can_manage_organization(user, tenant_key):
            raise HTTPException(status_code=403, detail="没有管理当前企业成员的权限")
        member = {**payload, "open_id": open_id}
        role_name = _field_text(member.get("role")).lower() or "member"
        status = _field_text(member.get("status")).lower() or "active"
        if status not in {"active", "disabled"}:
            raise HTTPException(status_code=400, detail="成员状态只能是 active 或 disabled")
        target_is_current_super_admin = bool(
            user.get("is_super_admin") and open_id in _identity_values(user)
        )
        if (service.is_super_admin(member, tenant_key) or target_is_current_super_admin) and (
            role_name != "admin" or status != "active"
        ):
            raise HTTPException(status_code=400, detail="默认超管不可停用或降级")
        existing_member = await service.store.member_for(member, tenant_key)
        existing_role = _field_text((existing_member or {}).get("role") or service.settings.default_role).lower()
        if not user.get("is_super_admin") and (role_name == "admin" or existing_role == "admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以授予或撤销管理员角色")
        member["is_tenant_admin"] = role_name == "admin" and not service.is_super_admin(member, tenant_key)
        try:
            if role_name not in await service.store.role_map(tenant_key):
                raise HTTPException(status_code=400, detail="成员角色不存在")
            result = await service.store.save_member({**member, "role": role_name, "status": status}, tenant_key)
            service._organization_expires_at[tenant_key] = 0
            return {**result, "role": result.get("role") or service.settings.default_role}
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def delete_member(request: Request, open_id: str, tenant_key: str = ""):
        user = await service.current_user(request)
        tenant_key = requested_tenant(user, tenant_key)
        if not service.can_manage_organization(user, tenant_key):
            raise HTTPException(status_code=403, detail="没有管理当前企业成员的权限")
        if service.is_super_admin({"open_id": open_id}, tenant_key):
            raise HTTPException(status_code=400, detail="默认超管不可移除授权")
        if open_id in _identity_values(user):
            raise HTTPException(status_code=400, detail="不能移除自己的成员授权")
        existing = await service.store.member_for({"open_id": open_id, "user_id": open_id}, tenant_key)
        existing_role = _field_text((existing or {}).get("role") or service.settings.default_role).lower()
        if not user.get("is_super_admin") and existing_role == "admin":
            raise HTTPException(status_code=403, detail="只有平台超管可以授予或撤销管理员角色")
        try:
            deleted = await service.store.delete_member({"open_id": open_id, "user_id": open_id}, tenant_key)
            service._organization_expires_at[tenant_key] = 0
            return {"deleted": deleted}
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def save_role(request: Request, role_name: str, payload: Dict[str, Any] = Body(...), tenant_key: str = ""):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理角色")
        tenant_key = requested_tenant(user, tenant_key)
        role_name = role_name.strip().lower()
        if not role_name or not role_name.replace("-", "").replace("_", "").isalnum():
            raise HTTPException(status_code=400, detail="角色标识只能包含字母、数字、下划线或连字符")
        permissions = list(dict.fromkeys(_json_list(payload.get("permissions"))))
        if set(permissions) - ROLE_PERMISSION_ALLOWLIST:
            raise HTTPException(status_code=400, detail="角色包含未知权限")
        try:
            result = await service.store.save_role({**payload, "name": role_name, "permissions": permissions, "system": role_name in DEFAULT_ROLES}, tenant_key)
            service._organization_expires_at[tenant_key] = 0
            return result
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def list_tenants(request: Request):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理企业租户")
        return {"tenants": service.list_tenants()}

    async def create_tenant(request: Request, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理企业租户")
        try:
            return service.save_tenant(payload)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async def update_tenant(request: Request, tenant_key: str, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理企业租户")
        try:
            update = {**payload, "tenant_key": tenant_key}
            return service.save_tenant(update)
        except FeishuAPIError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    async def delete_tenant(request: Request, tenant_key: str):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理企业租户")
        try:
            return {"deleted": service.remove_tenant(tenant_key)}
        except FeishuAPIError as exc:
            status = 409 if "至少保留一个" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    async def sync_tenant(request: Request, tenant_key: str):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以同步企业成员")
        try:
            result = await service.sync_directory(tenant_key)
            return {"tenant_key": result["tenant_key"], "departments": len(result["departments"]), "members": len(result["users"]), "synced_at": result["synced_at"]}
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=f"同步成员失败：{exc}") from exc

    async def sync_tenant_profile(request: Request, tenant_key: str):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以同步企业信息")
        if not service.tenant_exists(tenant_key):
            raise HTTPException(status_code=404, detail="企业不存在")
        try:
            tenant = await service.sync_tenant_profile(tenant_key, force=True, strict=True)
            return {"tenant_key": tenant["tenant_key"], "name": tenant["name"], "synced_at": int(time.time())}
        except FeishuAPIError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    async def create_tenant_invitation(request: Request, payload: Dict[str, Any] = Body(...)):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以生成企业接入邀请")
        try:
            minutes = max(5, min(int(payload.get("expires_in_minutes") or 60), 1440))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="邀请有效期格式无效")
        invitation = service.store.create_tenant_invitation(_field_text(payload.get("tenant_name")), minutes * 60)
        origin = str(request.base_url).rstrip("/")
        return {
            "invite_url": f"{origin}/static/tenant-onboarding.html?token={urllib.parse.quote(invitation['token'])}",
            "expires_at": invitation["expires_at"], "tenant_name": invitation["tenant_name"],
        }

    async def get_tenant_invitation(token: str):
        invitation = service.store.tenant_invitation(token)
        if not invitation:
            raise HTTPException(status_code=404, detail="邀请链接无效")
        if invitation["used"] or invitation["expired"]:
            raise HTTPException(status_code=410, detail="邀请链接已使用或已过期")
        return invitation

    async def accept_tenant_invitation(token: str, payload: Dict[str, Any] = Body(...)):
        tenant_key = _field_text(payload.get("tenant_key")).lower()
        if service.tenant_exists(tenant_key):
            raise HTTPException(status_code=409, detail="企业标识已存在")
        if not service.store.claim_tenant_invitation(token):
            raise HTTPException(status_code=410, detail="邀请链接已使用或已过期")
        success = False
        saved_tenant_key = ""
        try:
            verified = await service.verify_tenant_connection(payload)
            saved = service.save_tenant({**payload, "name": verified["enterprise_name"], "enabled": True})
            saved_tenant_key = saved["tenant_key"]
            profile = await service.sync_tenant_profile(saved_tenant_key, force=True, strict=True)
            try:
                directory = await service.sync_directory(saved_tenant_key)
            except FeishuAPIError as exc:
                raise FeishuAPIError(f"同步成员失败：{exc}") from exc
            saved = next(item for item in service.list_tenants() if item["tenant_key"] == saved_tenant_key)
            success = True
            return {
                "tenant": saved, "verified": True,
                "initial_sync": {
                    "name": profile["name"],
                    "departments": len(directory["departments"]),
                    "members": len(directory["users"]),
                },
                "login_url": "/",
            }
        except FeishuAPIError as exc:
            if saved_tenant_key:
                try:
                    service.remove_tenant(saved_tenant_key)
                except FeishuAPIError:
                    pass
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        finally:
            service.store.finish_tenant_invitation(token, success)

    async def delete_role(request: Request, role_name: str, tenant_key: str = ""):
        user = await service.current_user(request)
        if not user or not user.get("is_super_admin"):
            raise HTTPException(status_code=403, detail="只有平台超管可以管理角色")
        tenant_key = requested_tenant(user, tenant_key)
        try:
            deleted = await service.store.delete_role(role_name, tenant_key)
            service._organization_expires_at[tenant_key] = 0
            return {"deleted": deleted}
        except FeishuAPIError as exc:
            status = 409 if "仍被成员使用" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc

    app.add_api_route("/api/auth/config", auth_config, methods=["GET"])
    app.add_api_route("/api/auth/me", auth_me, methods=["GET"])
    app.add_api_route("/api/auth/local/login", local_login, methods=["POST"])
    app.add_api_route("/api/auth/feishu/login", auth_login, methods=["GET"])
    app.add_api_route("/t/{tenant_slug}/login", auth_login, methods=["GET"])
    app.add_api_route("/auth/callback", auth_callback, methods=["GET"])
    app.add_api_route("/api/auth/feishu/callback", auth_callback, methods=["GET"])
    app.add_api_route("/api/auth/logout", auth_logout, methods=["GET", "POST"])
    app.add_api_route("/api/admin/local-accounts", local_accounts, methods=["GET"])
    app.add_api_route("/api/admin/local-accounts", create_local_account, methods=["POST"])
    app.add_api_route("/api/admin/local-accounts/{account_id}", update_local_account, methods=["PATCH"])
    app.add_api_route("/api/admin/local-accounts/{account_id}", delete_local_account, methods=["DELETE"])
    app.add_api_route("/api/admin/organization", organization, methods=["GET"])
    app.add_api_route("/api/admin/tenants", list_tenants, methods=["GET"])
    app.add_api_route("/api/admin/tenants", create_tenant, methods=["POST"])
    app.add_api_route("/api/admin/tenants/{tenant_key}", update_tenant, methods=["PUT"])
    app.add_api_route("/api/admin/tenants/{tenant_key}", delete_tenant, methods=["DELETE"])
    app.add_api_route("/api/admin/tenants/{tenant_key}/sync", sync_tenant, methods=["POST"])
    app.add_api_route("/api/admin/tenants/{tenant_key}/sync-profile", sync_tenant_profile, methods=["POST"])
    app.add_api_route("/api/admin/tenant-invitations", create_tenant_invitation, methods=["POST"])
    app.add_api_route("/api/tenant-invitations/{token}", get_tenant_invitation, methods=["GET"])
    app.add_api_route("/api/tenant-invitations/{token}/accept", accept_tenant_invitation, methods=["POST"])
    app.add_api_route("/api/admin/members/{open_id}", save_member, methods=["PUT"])
    app.add_api_route("/api/admin/members/{open_id}", delete_member, methods=["DELETE"])
    app.add_api_route("/api/admin/roles/{role_name}", save_role, methods=["PUT"])
    app.add_api_route("/api/admin/roles/{role_name}", delete_role, methods=["DELETE"])

    async def tenant_name_sync_loop() -> None:
        while True:
            await service.sync_all_tenant_profiles(force=True)
            await asyncio.sleep(TENANT_NAME_SYNC_INTERVAL_SECONDS)

    async def start_tenant_name_sync() -> None:
        app.state.fy_tenant_name_sync_task = asyncio.create_task(tenant_name_sync_loop())

    async def stop_tenant_name_sync() -> None:
        task = getattr(app.state, "fy_tenant_name_sync_task", None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app.router.add_event_handler("startup", start_tenant_name_sync)
    app.router.add_event_handler("shutdown", stop_tenant_name_sync)


PUBLIC_AUTH_PATHS = {
    "/api/auth/config",
    "/api/auth/me",
    "/api/auth/feishu/login",
    "/api/auth/local/login",
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
    "/api/check-update", "/api/update-connectivity", "/api/update-connectivity/probe",
    "/api/update-backups", "/api/update-from-github", "/api/update-rollback",
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
    if path in PUBLIC_AUTH_PATHS or path.startswith("/api/tenant-invitations/") or (path.startswith("/t/") and path.endswith("/login")) or path in {"/static/login.html", "/static/tenant-onboarding.html"} or path.startswith("/static/images/") or path.startswith("/static/vendor/"):
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
    if any(path == item or path.startswith(item + "?") for item in SUPER_ADMIN_UPDATE_PATHS) and not user.get("is_super_admin"):
        return JSONResponse({"detail": "只有平台超管可以管理版本更新"}, status_code=403)
    required = _management_permission(path, method)
    if required and not service.has_permission(user, required):
        return JSONResponse({"detail": "没有修改设置的权限"}, status_code=403)
    if method not in SAFE_METHODS and path.startswith("/api/") and user.get("read_only") and path not in PUBLIC_AUTH_PATHS:
        return JSONResponse({"detail": "访客账号仅可查看，不能执行修改或生成操作"}, status_code=403)
    return await call_next(request)
