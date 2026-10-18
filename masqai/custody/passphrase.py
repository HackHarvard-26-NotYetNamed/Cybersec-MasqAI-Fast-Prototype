"""Passphrase custody (design: KeyEnigma.OpenRouter.doc.md §3.1): unseal the vault, then `DirectBackend`.

The management key lives in gateway RAM while the gateway runs. It is offered to the detectors as an `ADMIN_KEY`
secret, so it is masked if it ever appears in request content or logs, and it is wiped from its bytearray when the
backend closes.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable

import httpx

from .openrouter import DirectBackend, OpenRouterKeys, Sleep
from .vault import Unsealed, VaultError, default_path, tty_prompt, unlock


class PassphraseBackend(DirectBackend):
    mode = "passphrase"
    SECRET_TYPE = "ADMIN_KEY"

    def __init__(self, unsealed: Unsealed, *, workspace_id: str, instance_id: str,
                 transport: httpx.AsyncBaseTransport | None = None, sleep: Sleep = asyncio.sleep) -> None:
        if unsealed.provider != "openrouter":
            raise VaultError(f"the vault holds a {unsealed.provider!r} key, not an OpenRouter one")
        self._unsealed = unsealed
        self._secret = unsealed.reveal()
        super().__init__(OpenRouterKeys(self._secret, transport=transport), workspace_id=workspace_id,
                         instance_id=instance_id, management_expires_at=unsealed.management_expires_at, sleep=sleep)

    def __repr__(self) -> str:
        return f"PassphraseBackend({self.prefix}*, <management key hidden>)"

    def known_secrets(self) -> list[tuple[str, str]]:
        """The management key, for seed_entities() and scrub(). Never via custom_values (/api/config shows those)."""
        return [(self._secret, self.SECRET_TYPE)] if self._secret else []

    async def aclose(self) -> None:
        try:
            await super().aclose()
        finally:
            self._unsealed.wipe()
            self._secret = ""


def open_passphrase_backend(*, vault_path: str | Path | None, workspace_id: str, instance_id: str,
                            prompt: Callable[[str], str] = tty_prompt, attempts: int = 3,
                            transport: httpx.AsyncBaseTransport | None = None) -> PassphraseBackend:
    """Called by run_gateway before uvicorn starts. Prompts for the passphrase (refusing without a TTY)."""
    path = Path(vault_path).expanduser() if vault_path else default_path()
    unsealed = unlock(path, prompt, attempts=attempts)
    try:
        return PassphraseBackend(unsealed, workspace_id=workspace_id, instance_id=instance_id, transport=transport)
    except BaseException:
        unsealed.wipe()
        raise

