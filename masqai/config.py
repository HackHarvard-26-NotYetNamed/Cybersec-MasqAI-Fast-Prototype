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


class CustodyConfig(BaseModel):
    """Where the OpenRouter management key is kept (KeyEnigma.OpenRouter.doc.md §3). There is no default mode and no
    plaintext mode: the user chooses "passphrase" (an encrypted vault on this host) or "device" (an ESP32)."""
    model_config = ConfigDict(extra="forbid")

    mode: Literal["passphrase", "device"]
    vault_path: str | None = None          # passphrase: default ~/.masqai/openrouter.vault
    serial_port: str | None = None         # device
    device_id: str | None = None           # device
    pairing_file: str | None = None        # device: default ~/.masqai/device-<id>.pair

    @field_validator("vault_path", "serial_port", "device_id", "pairing_file", mode="before")
    @classmethod
    def _blank_is_none(cls, value: Any) -> Any:
        return None if value == "" else value

    @model_validator(mode="after")
    def _mode_fields(self) -> "CustodyConfig":
        if self.mode == "device":
            if not (self.serial_port and self.device_id):
                raise ValueError("device custody needs serial_port and device_id")
            if not re.fullmatch(r"esp32-[0-9a-f]{8}", self.device_id):
                raise ValueError("custody.device_id must look like esp32-1a2b3c4d (printed by python -m masqai.device enroll)")
        return self


ENIGMA_ORIGIN = "https://openrouter.ai"


class KeyEnigmaConfig(BaseModel):
    """Continuous rotation of this provider's upstream key (KeyEnigma.OpenRouter.doc.md §9). Fixed at startup."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    kind: Literal["openrouter"] = "openrouter"
    instance_id: str = Field(pattern=r"^[0-9a-f]{8}$")
    workspace_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    interval_seconds: float = Field(900.0, ge=300)
    jitter: float = Field(0.2, ge=0, le=0.5)
    drain_cap_seconds: float | None = Field(None, gt=0)   # None: the upstream timeout (no request outlives it)
    per_key_limit_usd: float = Field(2.0, gt=0, le=1000)
    failure_policy: Literal["closed", "open"] = "closed"
    custody: CustodyConfig

    @model_validator(mode="before")
    @classmethod
    def _helpful_required(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("instance_id"):
                import secrets
                raise ValueError(f"key_enigma.instance_id is required: 8 hex characters, generated once per install "
                                 f"and kept (it names this install's keys). For example: \"{secrets.token_hex(4)}\"")
            if not data.get("workspace_id"):
                raise ValueError("key_enigma.workspace_id is required: the id of a dedicated OpenRouter workspace "
                                 "that has a budget")
            custody = data.get("custody")
            if not isinstance(custody, dict) or custody.get("mode") in (None, ""):
                raise ValueError('key_enigma.custody.mode is required: "passphrase" or "device" (there is no default)')
        return data


class ProviderConfig(BaseModel):
    """Keys are referenced by environment variable only (the filesystem is untrusted).
    A provider without api_key_env sends no credentials, e.g. a local Ollama server."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    base_url: str
    api_key_env: str | None = None
    format: Literal["openai", "anthropic"] = "openai"
    headers: dict[str, str] = Field(default_factory=dict)
    key_enigma: KeyEnigmaConfig | None = None

    @property
    def rotates(self) -> bool:
        return bool(self.key_enigma and self.key_enigma.enabled)

    @model_validator(mode="after")
    def _enigma_origin(self) -> "ProviderConfig":
        # A rotated key is an OpenRouter key: it must never be sent to any other host.
        if self.rotates:
            from urllib.parse import urlsplit
            parts = urlsplit(self.base_url)
            if f"{parts.scheme}://{parts.netloc}".lower() != ENIGMA_ORIGIN:
                raise ValueError(f"provider {self.name!r}: key_enigma (kind openrouter) needs base_url on {ENIGMA_ORIGIN}")
        return self

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


# Markers of a prompt written for the prototype's operation set. Loading one fails fast instead of
# turning every request into a 502 (the prototype's stale-override bug).
STALE_PROMPT_MARKERS = ("\"op\":\"collapse\"", "MASQ_BLOCK")


class SecurityModelConfig(BaseModel):
    """The security model is given the new items, the N existing operations nearest to them (with k
    lines of context each), the mapping table, the whole conversation's user/assistant text, and the
    last `recent_items` tool results / reasoning items. Full mode is the same with N and k unlimited."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    provider: str | None = None
    model: str | None = None
    api_format: Literal["openai", "anthropic"] = "openai"
    # The security model reads raw context and the mapping table. A provider whose host is not
    # literally loopback is refused (before anything is sent) unless this is true.
    allow_remote_security_model: bool = False
    timeout_s: float = Field(60.0, gt=0)
    # The security model's context window in tokens (Ollama defaults to 4096). When a reply's
    # prompt + completion tokens reach it, the server may have truncated or shifted the context,
    # dropping the instructions, so the answer is not trusted: the request fails closed. 0 = unknown, no check.
    context_tokens: int = Field(0, ge=0)
    context_mode: Literal["recent", "full"] = "recent"
    recent_items: int = Field(12, ge=0)
    nearest_ops: int = Field(-1, ge=-1)          # -1 = all existing operations
    op_context_lines: int = Field(2, ge=0)       # lines shown above and below each existing operation
    # "auto": exact copies of known values are masked at word boundaries.
    # "auto_veto": the same, and the security model may undo one automatic copy with an `unmask` operation.
    auto_mask: Literal["auto", "auto_veto"] = "auto_veto"
    # What happens to an inbound tool call the guardrail rejects. "rewrite": the call is kept, but its
    # arguments become a harmless command that tells the untrusted model the user's security profile
    # rejected it, so the session continues. "error": the call is wiped and the client gets HTTP 400
    # (or, if text was already streamed, an error event that ends the stream).
    tool_rejection: Literal["rewrite", "error"] = "rewrite"
    # Empty = the built-in prompt in masqai/prompts/security.md.
    system_prompt: str = ""
    # Whether thinking / reasoning is enabled for the security model.
    # None = default behavior of model/provider.
    # False = disable thinking (e.g. reasoning_effort="none" or think=False).
    # True = enable thinking.
    think: bool | None = None

    @field_validator("provider", "model", mode="before")
    @classmethod
    def _blank_is_none(cls, value: Any) -> Any:
        return None if value == "" else value

    @field_validator("system_prompt")
    @classmethod
    def _current_prompt(cls, value: str) -> str:
        if value.strip():
            if any(marker in value for marker in STALE_PROMPT_MARKERS):
                raise ValueError("this prompt was written for the prototype (collapse / MASQ_BLOCK); clear it to use the built-in prompt")
            if "operations" not in value:
                raise ValueError('a custom prompt must ask for JSON {"operations": [...]}')
        return value


class CustomValue(BaseModel):
    """A literal value to always mask, e.g. a client name or an internal hostname."""
    type: str = Field("CUSTOM", pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    value: str = Field(min_length=3)


class DetectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    custom_values: list[CustomValue] = Field(default_factory=list)
    detect_host_identifiers: bool = True
    rules_dir: str = "masqai/rules"


class ProtectConfig(BaseModel):
    """What to protect, chosen by the user category by category (see masqai/policy.py). Off = values of that
    category are sent as they are. Custom values are always masked."""
    model_config = ConfigDict(extra="forbid")

    credentials: bool = True
    file_paths: bool = True
    machine_identity: bool = True
    emails: bool = True
    people: bool = True
    locations: bool = True
    infrastructure: bool = True
    documents: bool = True
    messages: bool = True


class RetentionConfig(BaseModel):
    """Sessions live in RAM only. Idle ones expire; past the cap the least recently used goes first.
    A session with a request in flight or an open stream is never evicted."""
    model_config = ConfigDict(extra="forbid")

    idle_ttl_h: float = Field(12.0, gt=0)
    max_sessions: int = Field(50, ge=1)


# Always dropped, in either mode: auth headers MasqAI sets itself for the configured provider, its own
# control headers, and hop-by-hop / framing headers that httpx must compute for the new connection.
# user-agent is replaced by headers.user_agent (see HeaderPolicy.user_agent).
ALWAYS_DROPPED_HEADERS = [
    "authorization", "proxy-authorization", "x-api-key", "x-masqai-*",
    "host", "content-length", "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "upgrade", "proxy-authenticate", "accept-encoding",
]
# Editable defaults. Blocklist: other providers' credentials, cookies, client fingerprints (OS, arch,
# runtime, SDK version), client session ids (read locally as soft hints first) and proxy / referer
# metadata. -retry-count and -timeout stay: they carry no identity.
DEFAULT_HEADER_BLOCKLIST = [
    "api-key", "x-goog-api-key", "cookie",
    "x-stainless-os", "x-stainless-arch", "x-stainless-runtime", "x-stainless-runtime-version",
    "x-stainless-package-version", "x-stainless-lang",
    "x-session-id", "session-id", "x-conversation-id", "conversation-id", "x-request-id",
    "x-forwarded-*", "x-real-ip", "forwarded", "via", "http-referer", "x-title",
]
DEFAULT_HEADER_ALLOWLIST = [
    "accept", "content-type", "openai-beta", "openai-organization", "openai-project",
    "anthropic-beta", "anthropic-version", "x-stainless-retry-count", "x-stainless-timeout",
]
DEFAULT_USER_AGENT = "masqai/0.2.0"


class HeaderPolicy(BaseModel):
    """Which client request headers reach the upstream.

    blocklist (default): forward everything except `blocklist` entries.
    allowlist: forward only `allowlist` entries.
    Entries are case-insensitive; a trailing `*` matches a prefix. ALWAYS_DROPPED_HEADERS are
    dropped in both modes; the provider's own auth and `provider.headers` are added afterwards.
    Headers named in the request's `Connection` header are hop-by-hop and also dropped.
    """
    model_config = ConfigDict(extra="forbid")

    mode: Literal["blocklist", "allowlist"] = "blocklist"
    # Replaces the client's User-Agent. Empty forwards the client's own.
    user_agent: str = DEFAULT_USER_AGENT
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
        if name.lower() == "user-agent" and self.user_agent:
            return False  # replaced, see upstream.headers_for
        if self.mode == "allowlist":
            return self._matches(name, self.allowlist)
        return not self._matches(name, self.blocklist)


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(8787, ge=1, le=65535)
    upstream_timeout_seconds: float = Field(180.0, gt=0)
    providers: list[ProviderConfig] = Field(default_factory=list)
    routes: dict[str, ModelRoute] = Field(default_factory=dict)
    default_route: ModelRoute | None = None
    security: SecurityModelConfig = Field(default_factory=SecurityModelConfig)
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    protect: ProtectConfig = Field(default_factory=ProtectConfig)
    headers: HeaderPolicy = Field(default_factory=HeaderPolicy)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    # Content types MasqAI can't inspect (images in OpenAI format, files, audio, ...): false refuses the
    # request with 422 before a session exists; true forwards them raw with a warning.
    pass_unknown: bool = False

    @field_validator("host")
    @classmethod
    def _loopback_only(cls, value: str) -> str:
        if value != "127.0.0.1":
            raise ValueError("MasqAI binds to 127.0.0.1 only")
        return value

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
