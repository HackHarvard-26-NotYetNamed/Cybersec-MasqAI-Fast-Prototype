"""Where upstream keys come from (Key Enigma, step 1: the seam, no rotation yet).

Every outbound call takes a *lease* on a key and releases it when the call (or stream) ends. Today the only
source is the provider's env var, read at lease time exactly as before. Key Enigma will add a rotating source
whose leases count in-flight requests, so an old key is revoked only after its last stream finishes.
Design: KeyEnigma.OpenRouter.doc.md.
"""
from __future__ import annotations

from typing import Callable, Protocol

from .config import ProviderConfig


class KeyLease:
    """One request's hold on a key. Release is idempotent; usable as a context manager."""

    __slots__ = ("key", "_on_release")

    def __init__(self, key: str | None, on_release: Callable[[], None] | None = None) -> None:
        self.key = key
        self._on_release = on_release

    def release(self) -> None:
        callback, self._on_release = self._on_release, None
        if callback is not None:
            callback()

    def __enter__(self) -> str | None:
        return self.key

    def __exit__(self, *_: object) -> None:
        self.release()


class KeySource(Protocol):
    def lease(self) -> KeyLease: ...
    def known_secrets(self) -> list[tuple[str, str]]: ...   # (value, TYPE): secrets the detectors must never let out


class EnvKeySource:
    """Today's behavior: the key named by provider.api_key_env, read on every lease. Nothing to count."""

    def __init__(self, provider: ProviderConfig) -> None:
        self.provider = provider

    def lease(self) -> KeyLease:
        return KeyLease(self.provider.resolved_key())

    def known_secrets(self) -> list[tuple[str, str]]:
        return []   # env keys are covered by the detector patterns, as before


class KeyRing:
    """Picks the key source for a provider. Providers without a registered source use their env var.

    Sources are looked up by provider name on every call, and the env fallback wraps the provider object it is
    given, so GUI config edits (which replace provider objects) take effect immediately, as before.
    """

    def __init__(self, sources: dict[str, KeySource] | None = None) -> None:
        self._sources: dict[str, KeySource] = dict(sources or {})

    def source(self, provider: ProviderConfig) -> KeySource:
        return self._sources.get(provider.name) or EnvKeySource(provider)

    def lease(self, provider: ProviderConfig) -> KeyLease:
        return self.source(provider).lease()

    def known_secrets(self) -> list[tuple[str, str]]:
        return [secret for source in self._sources.values() for secret in source.known_secrets()]
