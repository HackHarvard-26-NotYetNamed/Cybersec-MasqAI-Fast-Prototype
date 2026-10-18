"""One eval campaign, described by a single JSON document (the GUI edits it; the CLI loads it).

    {
      "name": "qwen-vs-gemini",
      "cases": "all" | ["uc2-db-path", ...],
      "runs": 3, "concurrency": 2, "sandbox": "local" | "daytona", "self_test": false,
      "conditions": [
        {"id": "raw",  "kind": "raw",    "untrusted": "google/gemini-3.8-flash"},
        {"id": "qwen", "kind": "masqai", "untrusted": "google/gemini-3.8-flash",
         "security": {"provider": "ollama-local", "model": "qwen3.5:4b", "think": false}}
      ],
      "gateway": { ...a MasqAI gateway config (masqai.json schema), shared by every masqai condition... },
      "agent": {...}, "harness": {...}, "relay": {...}, "services": {...}
    }

Conditions: `raw` = agent → relay → untrusted model (the unprotected baseline). `masqai` = agent → MasqAI
→ relay → untrusted model, with the condition's security model. Every masqai condition gets its own
gateway process built from the one shared `gateway` config; only the security provider/model (and
think) differ, plus the port and the route to the relay, which the harness owns. One relay serves all
conditions: the untrusted model travels in the model name `eval/<run_id>/<untrusted>`.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PRESETS_DIR = Path(__file__).parent / "presets"
RELAY_PROVIDER = "relay"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class SecuritySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1)    # a provider name from the shared gateway config
    model: str = Field(min_length=1)
    think: bool | None = None              # None = keep the gateway config's value


class ConditionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: Literal["raw", "masqai"]
    untrusted: str = Field(min_length=1)   # the model the relay forwards this condition's requests to
    security: SecuritySpec | None = None
    enabled: bool = True

    @field_validator("id")
    @classmethod
    def _slug(cls, value: str) -> str:
        if not ID_RE.fullmatch(value):
            raise ValueError("condition id: 1-32 chars of a-z 0-9 _ -, starting with a letter or digit")
        return value

    @model_validator(mode="after")
    def _security_for_masqai(self) -> "ConditionSpec":
        if self.kind == "masqai" and self.security is None:
            raise ValueError(f"condition {self.id!r}: a masqai condition needs a security model")
        if self.kind == "raw":
            self.security = None
        return self

    @property
    def label(self) -> str:
        if self.kind == "raw":
            return f"raw({self.untrusted})"
        return f"masqai({self.security.model}, {self.untrusted})"


class AgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_turns: int = Field(12, ge=1, le=200)
    command_timeout_s: int = Field(120, ge=1, le=3600)
    run_timeout_s: int = Field(900, ge=10, le=24 * 3600)
    max_tokens: int = Field(2048, ge=16, le=200_000)
    temperature: float = Field(0.0, ge=0, le=2)
    rate_limit_retries: int = Field(8, ge=0, le=50)
    http_timeout_s: float = Field(300, gt=0, le=3600)
    stream: bool = False


class HarnessSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seed_timeout_s: int = Field(120, ge=1, le=3600)
    check_timeout_s: int = Field(60, ge=1, le=3600)


class RelaySpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(8788, ge=1024, le=65535)
    upstream: str = "https://openrouter.ai/api"
    key_env: str = "OPENROUTER_API_KEY"    # "" = no upstream key (local upstream)
    max_records: int = Field(5000, ge=100)


class ServicesSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gateway_base_port: int = Field(8801, ge=1024, le=65000)
    ready_timeout_s: float = Field(60, gt=0, le=600)
    fake_llm_ports: tuple[int, int] = (8796, 8797)   # self-test only: agent model, security model


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "eval"
    cases: list[str] | Literal["all"] = "all"
    runs: int = Field(3, ge=1, le=1000)
    concurrency: int = Field(2, ge=1, le=64)
    sandbox: Literal["local", "daytona"] = "local"
    self_test: bool = False                 # scripted fake models; numbers are placeholders
    allow_local_untrusted: bool = False     # local sandbox + a real model: commands run on this machine
    publish: bool = False                   # copy results.json to web/public/data/ when done
    conditions: list[ConditionSpec]
    gateway: dict[str, Any] = Field(default_factory=dict)
    agent: AgentSpec = Field(default_factory=AgentSpec)
    harness: HarnessSpec = Field(default_factory=HarnessSpec)
    relay: RelaySpec = Field(default_factory=RelaySpec)
    services: ServicesSpec = Field(default_factory=ServicesSpec)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-.")[:48]
        return value or "eval"

    @model_validator(mode="after")
    def _checks(self) -> "RunConfig":
        if isinstance(self.cases, list) and not self.cases:
            raise ValueError("select at least one case")
        active = self.active_conditions
        if not active:
            raise ValueError("enable at least one condition")
        ids = [c.id for c in self.conditions]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate condition id(s): {', '.join(dupes)}")
        if self.sandbox == "local" and not self.self_test and not self.allow_local_untrusted:
            raise ValueError("the local sandbox runs a real model's commands on this machine: "
                             "use Daytona, self-test, or allow local untrusted commands explicitly")
        return self

    @property
    def active_conditions(self) -> list[ConditionSpec]:
        return [c for c in self.conditions if c.enabled]

    def gateway_port(self, condition: ConditionSpec) -> int:
        masq = [c.id for c in self.active_conditions if c.kind == "masqai"]
        return self.services.gateway_base_port + masq.index(condition.id)

    @property
    def relay_url(self) -> str:
        return f"http://127.0.0.1:{self.relay.port}"

    @property
    def relay_upstream(self) -> str:
        return f"http://127.0.0.1:{self.services.fake_llm_ports[0]}" if self.self_test else self.relay.upstream

    @property
    def relay_key_env(self) -> str:
        return "" if self.self_test else self.relay.key_env


def gateway_for(cfg: RunConfig, condition: ConditionSpec) -> dict[str, Any]:
    """The shared gateway config, specialised for one masqai condition. Validated by MasqAI's own schema."""
    from masqai.config import GatewayConfig
    data = copy.deepcopy(cfg.gateway)
    data["host"] = "127.0.0.1"
    data["port"] = cfg.gateway_port(condition)
    providers = [p for p in data.get("providers", []) if p.get("name") != RELAY_PROVIDER]
    providers.insert(0, {"name": RELAY_PROVIDER, "base_url": cfg.relay_url, "format": "openai"})
    data["providers"] = providers
    data["routes"] = {}
    data["default_route"] = {"provider": RELAY_PROVIDER, "model": None}   # the model name carries the run tag
    security = dict(data.get("security") or {})
    security.update(enabled=True, provider=condition.security.provider, model=condition.security.model)
    if condition.security.think is not None:
        security["think"] = condition.security.think
    data["security"] = security
    parsed = GatewayConfig.model_validate(data)
    if any(p.rotates for p in parsed.providers):
        raise ValueError("Key Enigma rotation needs an interactive custody prompt; disable key_enigma for eval gateways")
    return data


def problems(cfg: RunConfig) -> list[dict[str, str]]:
    """Static checks the GUI shows before Start (no network). [{"level": "error"|"warn", "where", "msg"}]."""
    import os
    import shutil
    from masqai.config import is_loopback_url, validation_errors
    out: list[dict[str, str]] = []
    try:
        from .cases import load_cases
        load_cases(cfg.cases if cfg.cases == "all" else ",".join(cfg.cases))
    except BaseException as exc:   # load_cases raises SystemExit on unknown ids
        out.append({"level": "error", "where": "cases", "msg": str(exc)})
    for condition in cfg.active_conditions:
        if condition.kind != "masqai":
            continue
        try:
            data = gateway_for(cfg, condition)
        except Exception as exc:
            for err in validation_errors(exc):
                where = ".".join(map(str, err["loc"])) or "gateway"
                out.append({"level": "error", "where": f"{condition.id}: {where}", "msg": err["msg"]})
            continue
        provider = next(p for p in data["providers"] if p["name"] == condition.security.provider)
        remote = not is_loopback_url(provider["base_url"])
        if remote and not data["security"].get("allow_remote_security_model"):
            out.append({"level": "error", "where": f"{condition.id}: security",
                        "msg": f"provider {provider['name']!r} is remote; set security.allow_remote_security_model or every request fails closed"})
        if provider.get("api_key_env") and not os.getenv(provider["api_key_env"]):
            out.append({"level": "error", "where": f"{condition.id}: security",
                        "msg": f"{provider['api_key_env']} is not set (security provider {provider['name']!r})"})
    if cfg.relay_key_env and not os.getenv(cfg.relay_key_env):
        out.append({"level": "error", "where": "relay", "msg": f"{cfg.relay_key_env} is not set (the relay's upstream key)"})
    if cfg.sandbox == "daytona" and not os.getenv("DAYTONA_API_KEY"):
        out.append({"level": "error", "where": "sandbox", "msg": "DAYTONA_API_KEY is not set"})
    if cfg.sandbox == "local":
        from .sandbox import _find_bash
        try:
            _find_bash()
        except RuntimeError as exc:
            out.append({"level": "error", "where": "sandbox", "msg": str(exc)})
        if not cfg.self_test:
            out.append({"level": "warn", "where": "sandbox", "msg": "local sandbox: the untrusted model's commands run on this machine"})
    if cfg.self_test and cfg.sandbox != "local":
        out.append({"level": "warn", "where": "sandbox", "msg": "self-test is meant for the local sandbox"})
    ports = [cfg.relay.port] + [cfg.gateway_port(c) for c in cfg.active_conditions if c.kind == "masqai"]
    if cfg.self_test:
        ports += list(cfg.services.fake_llm_ports)
    if len(set(ports)) != len(ports):
        out.append({"level": "error", "where": "services", "msg": f"port clash among {ports}"})
    if shutil.which("git") is None:
        out.append({"level": "warn", "where": "host", "msg": "git not on PATH (uc5 seeds git history)"})
    return out


def load_run_config(path: str | Path) -> RunConfig:
    return RunConfig.model_validate(json.loads(Path(path).read_text(encoding="utf-8-sig")))


def presets() -> dict[str, dict[str, Any]]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8-sig")) for p in sorted(PRESETS_DIR.glob("*.json"))}
