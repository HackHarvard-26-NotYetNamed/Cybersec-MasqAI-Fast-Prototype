"""Management-key custody for Key Enigma (design: KeyEnigma.OpenRouter.doc.md §3).

The rotation state machine (enigma.py) talks only to a `ManagementBackend`. Two backends: `passphrase` (the
management key is decrypted into gateway RAM; passphrase.py) and `device` (the key stays on an ESP32; device.py).
Both expose the same operations, so rotation logic does not depend on where the key lives.

There is deliberately no plaintext env-var backend; tests use an in-memory fake (tests/helpers.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Literal, Mapping, Protocol, runtime_checkable

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


def load_backend(custody: Any, *, workspace_id: str | None = None, instance_id: str | None = None,
                 prompt: Callable[[str], str] | None = None, transport: Any = None) -> ManagementBackend:
    """Open the backend the user chose. There is no default mode: the choice is explicit (owner decision).

    `custody` is a key_enigma.custody block (a CustodyConfig or a plain mapping). Passphrase mode prompts for the
    passphrase through `prompt` (default: getpass on a real terminal, refusing without one)."""
    if hasattr(custody, "model_dump"):
        custody = custody.model_dump()
    mode = custody.get("mode") if isinstance(custody, Mapping) else None
    if mode not in CUSTODY_MODES:
        raise CustodyError(f"key_enigma.custody.mode must be one of {', '.join(CUSTODY_MODES)} (got {mode!r}); there is no default")
    if not workspace_id or not instance_id:
        raise CustodyError(f"{mode} custody needs the workspace_id and instance_id from key_enigma")
    if mode == "device":
        from .device import open_device_backend
        if not custody.get("serial_port") or not custody.get("device_id"):
            raise CustodyError("device custody needs serial_port and device_id")
        return open_device_backend(serial_port=custody["serial_port"], device_id=custody["device_id"],
                                   pairing_file=custody.get("pairing_file"), workspace_id=workspace_id,
                                   instance_id=instance_id, transport=transport)
    from .passphrase import open_passphrase_backend
    from .vault import tty_prompt
    return open_passphrase_backend(vault_path=custody.get("vault_path"), workspace_id=workspace_id,
                                   instance_id=instance_id, prompt=prompt or tty_prompt, transport=transport)
