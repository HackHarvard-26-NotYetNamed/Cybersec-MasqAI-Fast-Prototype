"""Management-key custody for Key Enigma (design: KeyEnigma.OpenRouter.doc.md §3).

The rotation state machine (enigma.py, build step 3) talks only to a `ManagementBackend`. Two backends are planned:
`passphrase` (the management key is decrypted into gateway RAM; step 6) and `device` (the key stays on an ESP32;
steps 7-8). Both expose the same five operations, so rotation logic does not depend on where the key lives.

There is deliberately no plaintext env-var backend; tests use an in-memory fake (tests/helpers.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping, Protocol, runtime_checkable

CUSTODY_MODES = ("passphrase", "device")


class CustodyError(RuntimeError):
    """A management operation failed. Messages never contain key values."""


class ManagementAuthError(CustodyError):
    """The management key was refused (401/403): revoked, expired or lacking permission. Retrying soon is pointless."""


class RateLimited(CustodyError):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class BackendUnavailable(CustodyError):
    """Network failure, timeout or a 5xx: worth retrying with backoff."""


class KeyNotFound(CustodyError):
    pass


class WorkspaceUnbudgeted(CustodyError):
    """The Enigma workspace has no budget. Startup refuses (owner decision, §7)."""


@dataclass(frozen=True)
class MintedKey:
    """A freshly created inference key. `key` is shown by OpenRouter once and is never printed or persisted."""
    key: str = field(repr=False)
    hash: str
    name: str
    expires_at: datetime
    limit_usd: float


@dataclass(frozen=True)
class BackendStatus:
    mode: str
    healthy: bool
    detail: str = ""
    management_expires_at: datetime | None = None
    # Device mode: the caps enforced by firmware policy. None means "no cap beyond config".
    max_limit_usd: float | None = None
    max_ttl_seconds: int | None = None


RevokeOutcome = Literal["deleted", "disabled", "already_gone"]


@runtime_checkable
class ManagementBackend(Protocol):
    # The backend builds the full name, `masqai-enigma-<instance_id>-<suffix>`, so a caller can't mint (or later
    # clean up) keys outside this install's prefix. In device mode the firmware enforces the same rule.
    async def mint(self, *, suffix: str, expires_at: datetime, limit_usd: float) -> MintedKey: ...
    async def revoke(self, key_hash: str) -> RevokeOutcome: ...   # DELETE, falling back to PATCH disabled
    async def usage(self, key_hash: str) -> float: ...
    async def cleanup(self) -> int: ...                           # delete leftovers from earlier runs
    async def status(self) -> BackendStatus: ...
    async def aclose(self) -> None: ...


def load_backend(custody: Mapping[str, Any]) -> ManagementBackend:
    """Open the backend the user chose. There is no default mode: the choice is explicit (owner decision)."""
    mode = custody.get("mode")
    if mode not in CUSTODY_MODES:
        raise CustodyError(f"key_enigma.custody.mode must be one of {', '.join(CUSTODY_MODES)} (got {mode!r}); there is no default")
    step = {"passphrase": 6, "device": 8}[mode]
    raise CustodyError(f"custody mode {mode!r} is not built yet (KeyEnigma build step {step}); Key Enigma cannot start")
