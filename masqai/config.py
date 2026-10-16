from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CREDENTIAL_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "api-key", "x-goog-api-key"}
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def is_loopback_url(url: str) -> bool:
    """True if the URL's host is literally this machine. No DNS lookup: a name that merely resolves
    to 127.0.0.1 today (rebinding, hosts file) does not count, except `localhost` itself."""
    import ipaddress
    from urllib.parse import urlsplit
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ConfigReferenceError(ValueError):
    """A cross-field config error that knows which field it belongs to."""

    def __init__(self, loc: tuple, message: str) -> None:
        super().__init__(message)
        self.loc = loc
        self.message = message


def validation_errors(exc: Exception) -> list[dict[str, Any]]:
    """Flatten a config validation failure into [{"loc": [...], "msg": "..."}] for the GUI."""
    from pydantic import ValidationError
    if isinstance(exc, ValidationError):
        out = []
        for error in exc.errors():
            ctx = (error.get("ctx") or {}).get("error")
            if isinstance(ctx, ConfigReferenceError):
                out.append({"loc": list(ctx.loc), "msg": ctx.message})
            else:
                msg = error["msg"].removeprefix("Value error, ")
                out.append({"loc": [p for p in error["loc"] if not (isinstance(p, str) and p.startswith("function-"))], "msg": msg})
        return out
    if isinstance(exc, ConfigReferenceError):
        return [{"loc": list(exc.loc), "msg": exc.message}]
    return [{"loc": [], "msg": str(exc)}]


class ProviderConfig(BaseModel):
    """Keys are referenced by environment variable only (the filesystem is untrusted).
    A provider without api_key_env sends no credentials, e.g. a local Ollama server."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    base_url: str
    api_key_env: str | None = None
    format: Literal["openai", "anthropic"] = "openai"
    headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _no_literal_keys(cls, data: Any) -> Any:
        if isinstance(data, dict) and "api_key" in data:
            if data["api_key"] not in (None, "", "<configured>"):
                raise ValueError(f"provider {data.get('name')!r}: literal api_key is not allowed; set api_key_env to an environment variable name")
            data = {k: v for k, v in data.items() if k != "api_key"}
        return data

    @field_validator("base_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if not re.match(r"https?://[^/\s]+", value or ""):
            raise ValueError("must start with http:// or https:// followed by a host")
        return value

    @field_validator("api_key_env", mode="before")
    @classmethod
    def _env_name(cls, value: Any) -> Any:
        if value in ("", None):
            return None
        if not isinstance(value, str) or not ENV_NAME_RE.fullmatch(value):
            raise ValueError("must be an environment variable NAME (letters, digits, _), not the key itself")
        return value

    @field_validator("headers")
    @classmethod
    def _no_credential_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        for name in headers:
            if not name.strip():
                raise ValueError("header names must not be empty")
            if name.lower() in CREDENTIAL_HEADERS:
                raise ValueError(f"header {name!r} carries a credential; use api_key_env instead")
        return headers

    def resolved_key(self) -> str | None:
        return os.getenv(self.api_key_env) if self.api_key_env else None


class ModelRoute(BaseModel):
    provider: str = Field(min_length=1)
    model: str | None = None

    @field_validator("model", mode="before")
    @classmethod
    def _blank_is_none(cls, value: Any) -> Any:
        return None if value == "" else value


class SecurityModelConfig(BaseModel):
    """The security model is given the new items, the N existing operations nearest to them (with k
    lines of context each), the mapping table, the whole conversation's user/assistant text, and the
    last `recent_items` tool results / reasoning items. Full mode is the same with N and k unlimited."""
    enabled: bool = True
    provider: str | None = None
    model: str | None = None
    api_format: Literal["openai", "anthropic"] = "openai"
    timeout_seconds: float = Field(45.0, gt=0)
    context_mode: Literal["recent", "full"] = "recent"
    recent_items: int = Field(12, ge=0)
    nearest_ops: int = Field(-1, ge=-1)          # -1 = all existing operations
    op_context_lines: int = Field(2, ge=0)       # lines shown above and below each existing operation
    # "auto": exact copies of known values are masked at token boundaries.
    # "auto_veto": the same, and the security model may undo one automatic copy with an `unmask` operation.
    auto_mask: Literal["auto", "auto_veto"] = "auto"
    system_prompt: str = ""

    @field_validator("provider", "model", mode="before")
    @classmethod
    def _blank_is_none(cls, value: Any) -> Any:
        return None if value == "" else value


class CustomValue(BaseModel):
    """A literal value to always mask, e.g. a client name or an internal hostname."""
    type: str = Field("CUSTOM", pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    value: str = Field(min_length=3)


class DetectorConfig(BaseModel):
    custom_values: list[CustomValue] = Field(default_factory=list)
    detect_host_identifiers: bool = True


# Always dropped, in either mode: auth headers MasqAI sets itself for the configured provider,
# and hop-by-hop / framing headers that httpx must compute for the new connection.
ALWAYS_DROPPED_HEADERS = [
    "authorization", "proxy-authorization", "x-api-key",
    "host", "content-length", "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "upgrade", "proxy-authenticate", "accept-encoding",
]
# Editable defaults. Blocklist: other providers' credentials and cookies. Everything else is
# forwarded so the gateway stays transparent.
DEFAULT_HEADER_BLOCKLIST = ["api-key", "x-goog-api-key", "cookie"]
DEFAULT_HEADER_ALLOWLIST = [
    "accept", "content-type", "user-agent", "openai-beta", "openai-organization", "openai-project",
    "anthropic-beta", "anthropic-version", "http-referer", "x-title", "x-stainless-*",
]


class HeaderPolicy(BaseModel):
    """Which client request headers reach the upstream.

    blocklist (default): forward everything except `blocklist` entries.
    allowlist: forward only `allowlist` entries.
    Entries are case-insensitive; a trailing `*` matches a prefix. ALWAYS_DROPPED_HEADERS are
    dropped in both modes; the provider's own auth and `provider.headers` are added afterwards.
    Headers named in the request's `Connection` header are hop-by-hop and also dropped.
    """
    mode: Literal["blocklist", "allowlist"] = "blocklist"
    blocklist: list[str] = Field(default_factory=lambda: list(DEFAULT_HEADER_BLOCKLIST))
    allowlist: list[str] = Field(default_factory=lambda: list(DEFAULT_HEADER_ALLOWLIST))

    @staticmethod
    def _matches(name: str, entries: list[str]) -> bool:
        name = name.lower()
        for entry in entries:
            entry = entry.strip().lower()
            if (entry.endswith("*") and name.startswith(entry[:-1])) or name == entry:
                return True
        return False

    def allows(self, name: str) -> bool:
        if self._matches(name, ALWAYS_DROPPED_HEADERS):
            return False
        if self.mode == "allowlist":
            return self._matches(name, self.allowlist)
        return not self._matches(name, self.blocklist)


class GatewayConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(8787, ge=1, le=65535)
    upstream_timeout_seconds: float = Field(180.0, gt=0)
    providers: list[ProviderConfig] = Field(default_factory=list)
    routes: dict[str, ModelRoute] = Field(default_factory=dict)
    default_route: ModelRoute | None = None
    security: SecurityModelConfig = Field(default_factory=SecurityModelConfig)
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    headers: HeaderPolicy = Field(default_factory=HeaderPolicy)
    allow_remote_security_model: bool = True

    @model_validator(mode="after")
    def _references(self) -> "GatewayConfig":
        """Cross-field checks, raised with a precise location so the GUI can mark the field."""
        names = [p.name for p in self.providers]
        for index, name in enumerate(names):
            if name in names[:index]:
                raise ConfigReferenceError(("providers", index, "name"), f"duplicate provider name {name!r}")
        known = set(names)
        for alias, route in self.routes.items():
            if not alias.strip():
                raise ConfigReferenceError(("routes",), "route alias must not be empty")
            if route.provider not in known:
                raise ConfigReferenceError(("routes", alias, "provider"), f"unknown provider {route.provider!r}")
        if self.default_route and self.default_route.provider not in known:
            raise ConfigReferenceError(("default_route", "provider"), f"unknown provider {self.default_route.provider!r}")
        if self.security.provider and self.security.provider not in known:
            raise ConfigReferenceError(("security", "provider"), f"unknown provider {self.security.provider!r}")
        return self

    def provider(self, name: str) -> ProviderConfig:
        for provider in self.providers:
            if provider.name == name:
                return provider
        raise KeyError(f"Unknown provider: {name}")

    def route(self, model: str | None) -> tuple[ProviderConfig, str | None]:
        route = self.routes.get(model or "") or self.default_route
        if route is None:
            raise ValueError(f"No route configured for model {model!r}")
        return self.provider(route.provider), route.model or model


def load_config(path: str | Path) -> GatewayConfig:
    raw: dict[str, Any] = {}
    config_path = Path(path)
    if config_path.exists():
        raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
    return GatewayConfig.model_validate(raw)
