"""Where upstream keys come from (Key Enigma).

Every outbound call takes a *lease* on a key and releases it when the call (or stream) ends. Providers without a
rotating source use their env var, read at lease time exactly as before (`EnvKeySource`). `EnigmaKeySource` rotates
keys minted through a `ManagementBackend`; its leases count in-flight requests, so an old key is revoked only after
its last stream finishes, or when the drain cap passes. Design: KeyEnigma.OpenRouter.doc.md §4, §5.
"""
from __future__ import annotations

import asyncio
import math
import random
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Protocol

from . import logs
from .config import ProviderConfig
from .custody import CustodyError, ManagementAuthError, ManagementBackend, MintedKey, RateLimited


class KeyUnavailable(RuntimeError):
    """No validated key is active, so the request is refused before anything is sent (fail closed). HTTP 503."""


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

    async def start(self) -> None:
        """Called by the app's lifespan before it accepts traffic: rotating sources obtain their first key."""
        for source in self._sources.values():
            start = getattr(source, "start", None)
            if start is not None:
                await start()

    async def stop(self) -> None:
        for source in self._sources.values():
            stop = getattr(source, "stop", None)
            if stop is not None:
                await stop()


# ------------------------------------------------------------------------------------------------------------------
# Key Enigma: the rotating source
# ------------------------------------------------------------------------------------------------------------------

MIN_INTERVAL_SECONDS = 300.0

# Key states (§4). STANDBY: validated, waiting for the current interval to end.
VALIDATING, STANDBY, ACTIVE, DRAINING, REVOKING = "validating", "standby", "active", "draining", "revoking"
REVOKED, DEAD, REVOKE_FAILED, DISCARDED = "revoked", "dead", "revoke_failed", "discarded"


@dataclass(frozen=True)
class RotationPolicy:
    """Timing and money limits for one rotating provider (§5, §7). Values are checked here, not only in config."""
    interval_seconds: float = 900.0
    jitter: float = 0.2
    lead_seconds: float = 60.0              # the successor is minted this long before the interval ends
    drain_cap_seconds: float = 600.0        # derived from the upstream timeout: no request outlives it
    safety_margin_seconds: float = 120.0    # clock skew between us and OpenRouter
    per_key_limit_usd: float = 2.0
    validate_window_seconds: float = 10.0   # creation propagation: a new key must answer 200 within this
    settle_seconds: float = 5.0             # wait for late charges before reading a key's final usage
    confirm_window_seconds: float = 120.0   # probe a revoked key this long for the first 401
    confirm_every_seconds: float = 2.0

    def __post_init__(self) -> None:
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in vars(self).values()):
            raise ValueError("rotation policy values must be finite numbers")
        if self.interval_seconds < MIN_INTERVAL_SECONDS:
            raise ValueError(f"interval_seconds must be at least {MIN_INTERVAL_SECONDS:.0f}")
        if not 0 <= self.jitter <= 0.5:
            raise ValueError("jitter must be between 0 and 0.5")
        if not 0 < self.lead_seconds < self.interval_seconds * (1 - self.jitter):
            raise ValueError("lead_seconds must be positive and shorter than the shortest interval")
        if self.drain_cap_seconds <= 0 or self.per_key_limit_usd <= 0:
            raise ValueError("drain_cap_seconds and per_key_limit_usd must be positive")
        if min(self.safety_margin_seconds, self.settle_seconds) < 0:
            raise ValueError("safety_margin_seconds and settle_seconds must not be negative")
        if min(self.validate_window_seconds, self.confirm_window_seconds, self.confirm_every_seconds) <= 0:
            raise ValueError("validation and confirmation windows must be positive")

    @property
    def ttl_seconds(self) -> float:
        """expires_at - now at mint time: the hard ceiling on a key's life, enforced by OpenRouter (§5)."""
        return self.interval_seconds * (1 + self.jitter) + self.lead_seconds + self.drain_cap_seconds + self.safety_margin_seconds


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def utcnow(self) -> datetime: ...
    async def sleep(self, seconds: float) -> None: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def utcnow(self) -> datetime:
        return datetime.now(timezone.utc)

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds))


@dataclass(eq=False)
class KeyRecord:
    minted: MintedKey = field(repr=False)  # key value and full hash stay out of reprs, logs and tracebacks
    label: str
    state: str
    minted_at: float
    activated_at: float | None = None
    deadline: float | None = None         # monotonic: when the interval ends and the key stops taking leases
    retired_at: float | None = None
    revoked_at: float | None = None
    dead_at: float | None = None
    refcount: int = 0
    forced: bool = False                  # revoked by the drain cap with leases still open
    usage_usd: float | None = None
    revoke_outcome: str | None = None
    announced: bool = False
    idle: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    @property
    def short_hash(self) -> str:
        return self.minted.hash[:8]

    def __repr__(self) -> str:
        return f"KeyRecord({self.label}, {self.short_hash}, {self.state}, refcount={self.refcount})"


Probe = Callable[[str], Awaitable[bool]]


async def _default_probe(key: str) -> bool:
    from .custody.openrouter import probe_key
    return await probe_key(key)


class EnigmaKeySource:
    """Rotates one provider's key: mint ahead, validate, swap at the interval end, drain, revoke, confirm dead.

    One key is ACTIVE. Its successor is minted `lead_seconds` before the interval ends, validated, and parked as
    STANDBY. The swap happens in `_swap_locked`, under a lock with no await. Whichever comes first does it: the
    rotation task at the deadline, or the first lease after the deadline. So every request holds exactly one key,
    old or new (§4), and no key takes leases past its interval, even if the rotation task is late or has crashed.

    The failure policy here is `closed` (the default, §8). If the interval ends with no validated successor, leases
    raise KeyUnavailable until one exists. Requests already in flight keep their old key until the drain ends.
    """

    SECRET_TYPE = "OR_KEY"

    def __init__(self, name: str, backend: ManagementBackend, policy: RotationPolicy | None = None, *,
                 clock: Clock | None = None, probe: Probe | None = None, rng: Any = None) -> None:
        self.name = name
        self.backend = backend
        self.policy = policy or RotationPolicy()
        self.clock = clock or SystemClock()
        self.probe = probe or _default_probe
        self.rng = rng or random.SystemRandom()      # an observer must not predict when keys switch
        self._lock = threading.Lock()                # leases may come from worker threads (TestClient, sync code)
        self._active: KeyRecord | None = None
        self._standby: KeyRecord | None = None
        self._records: list[KeyRecord] = []          # every key that may still work (not confirmed dead or expired)
        self.history: deque[KeyRecord] = deque(maxlen=20)
        self.events: deque[dict[str, Any]] = deque(maxlen=50)
        self.propagation_seconds: list[float] = []
        self.spend_usd = 0.0
        self._run_id = secrets.token_hex(2)          # names stay unique across restarts of one install
        self._seq = 0
        self._task: asyncio.Task | None = None
        self._tasks: set[asyncio.Task] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopped = True

    # ---------- leases: synchronous, on the request path ----------
    def lease(self) -> KeyLease:
        retired = None
        with self._lock:
            if self._stopped or self._active is None:
                raise KeyUnavailable(f"no validated key for {self.name} (fail closed)")
            if self.clock.monotonic() >= self._active.deadline:
                retired = self._swap_locked()
                if self._active is None:
                    self._after_swap(retired)
                    raise KeyUnavailable(f"the key interval for {self.name} ended without a validated successor (fail closed)")
            record = self._active
            record.refcount += 1
        if retired is not None:
            self._after_swap(retired)
        return KeyLease(record.minted.key, lambda: self._release(record))

    def _release(self, record: KeyRecord) -> None:
        with self._lock:
            record.refcount -= 1
            idle = record.refcount <= 0 and record.state != ACTIVE
        if idle:
            self._call_on_loop(record.idle.set)

    def _swap_locked(self) -> KeyRecord | None:
        """Retire the active key and promote the standby, if any. Caller holds the lock. Returns the retired key."""
        retired, successor = self._active, self._standby
        self._standby = None
        if retired is not None:
            retired.state = DRAINING
            retired.retired_at = self.clock.monotonic()
        self._active = None
        if successor is not None:
            self._start_interval_locked(successor)
        return retired

    def _start_interval_locked(self, record: KeyRecord) -> None:
        now = self.clock.monotonic()
        jitter = self.policy.jitter
        interval = self.policy.interval_seconds * self.rng.uniform(1 - jitter, 1 + jitter)
        # A key must never take leases so late that a request could outlive its expires_at.
        left = ((record.minted.expires_at - self.clock.utcnow()).total_seconds()
                - self.policy.drain_cap_seconds - self.policy.safety_margin_seconds)
        record.activated_at = now
        record.deadline = now + max(0.0, min(interval, left))
        record.state = ACTIVE
        self._active = record

    def _after_swap(self, retired: KeyRecord | None) -> None:
        """Outside the lock: log the swap and start draining the retired key. Safe to call from any thread."""
        active = self._active
        if active is not None and not active.announced:
            active.announced = True
            self._event("activated", active)
            logs.log.info("enigma %s: %s (%s) active for %.0f s", self.name, active.label, active.short_hash,
                          active.deadline - active.activated_at)
        if retired is not None:
            if active is None:
                self._event("interval_ended_without_successor", retired)
                logs.log.error("enigma %s: %s's interval ended with no validated successor; refusing requests (fail closed)",
                               self.name, retired.label)
            self._call_on_loop(self._spawn, self._drain_and_revoke(retired))

    def _call_on_loop(self, fn: Callable[..., Any], *args: Any) -> None:
        loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if loop is None or running is loop:
            fn(*args)
        else:
            loop.call_soon_threadsafe(fn, *args)

    def known_secrets(self) -> list[tuple[str, str]]:
        """Every key value that may still work: active, standby, draining, and revoked but not confirmed dead."""
        now = self.clock.utcnow()
        with self._lock:
            return [(r.minted.key, self.SECRET_TYPE) for r in self._records if r.minted.expires_at > now]

    @property
    def active(self) -> KeyRecord | None:
        return self._active

    # ---------- lifecycle ----------
    async def start(self, attempts: int = 3) -> None:
        """Obtain and activate the first key before the gateway accepts traffic. Raises KeyUnavailable on failure."""
        self._loop = asyncio.get_running_loop()
        delay = 2.0
        for attempt in range(attempts):
            try:
                record = await self._mint_and_validate()
                break
            except Exception as exc:   # noqa: BLE001 - logged as an event; startup fails closed below
                self._event("mint_failed", detail=f"{type(exc).__name__}: {exc}")
                if isinstance(exc, ManagementAuthError) or attempt + 1 == attempts:
                    raise KeyUnavailable(f"could not obtain a first key for {self.name}: {logs_safe(str(exc))}") from None
                await self.clock.sleep(delay)
                delay *= 2
        with self._lock:
            self._stopped = False
            self._start_interval_locked(record)
        self._after_swap(None)
        self._task = asyncio.create_task(self._run(), name=f"enigma-{self.name}")

    async def stop(self) -> None:
        """Refuse new leases, stop rotating, and revoke every key that may still work (best effort, bounded)."""
        with self._lock:
            self._stopped = True
            self._active = self._standby = None
        tasks = [t for t in (self._task, *self._tasks) if t is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._task = None
        pending = [r for r in self._records if r.state != REVOKED]
        if pending:
            try:
                await asyncio.wait_for(asyncio.gather(*(self._revoke(r, settle=False, confirm=False) for r in pending),
                                                      return_exceptions=True), timeout=15)
            except asyncio.TimeoutError:
                logs.log.warning("enigma %s: shutdown revocation timed out; the remaining keys die at expires_at", self.name)

    # ---------- the rotation loop ----------
    async def _run(self) -> None:
        try:
            while not self._stopped:
                current = self._active
                if current is None:
                    successor = await self._obtain()            # fail-closed gap: recover as soon as possible
                    with self._lock:
                        if not self._stopped:
                            self._start_interval_locked(successor)
                            successor = None
                    if successor is not None:
                        await self._revoke(successor, settle=False)
                    self._after_swap(None)
                    continue
                await self._sleep_until(current.deadline - self.policy.lead_seconds)
                successor = await self._obtain_before(current.deadline)
                if successor is not None:
                    with self._lock:
                        if self._active is current and not self._stopped:
                            self._standby = successor
                            successor = None
                    if successor is not None:                  # stopped meanwhile: it was never needed
                        self._spawn(self._revoke(successor, settle=False))
                await self._sleep_until(current.deadline)
                retired = None
                with self._lock:
                    if self._active is current:                 # a lease may already have swapped
                        retired = self._swap_locked()
                self._after_swap(retired)
                self._prune()
        except asyncio.CancelledError:
            raise
        except Exception:   # noqa: BLE001 - leases still stop at the deadline
            logs.log.exception("enigma %s: rotation loop crashed; requests stop when the current interval ends", self.name)
            self._event("rotation_crashed")

    async def _obtain_before(self, deadline: float) -> KeyRecord | None:
        """A validated successor, or None if the deadline passes first (the search then continues after the swap)."""
        task = asyncio.ensure_future(self._obtain())
        timer = asyncio.ensure_future(self._sleep_until(deadline))
        try:
            await asyncio.wait({task, timer}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            timer.cancel()
        if task.done():
            return task.result()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return None

    async def _sleep_until(self, when: float | None) -> None:
        if when is not None:
            delay = when - self.clock.monotonic()
            if delay > 0:
                await self.clock.sleep(delay)

    async def _obtain(self) -> KeyRecord:
        """Mint and validate a key, retrying with backoff until one works (§8)."""
        delay = 2.0
        while True:
            try:
                return await self._mint_and_validate()
            except asyncio.CancelledError:
                raise
            except ManagementAuthError as exc:
                self._event("management_key_refused", detail=str(exc))
                logs.log.critical("enigma %s: the management key was refused; retrying in 5 min", self.name)
                wait = 300.0
            except RateLimited as exc:
                self._event("mint_rate_limited")
                wait = exc.retry_after if exc.retry_after is not None else delay
            except Exception as exc:   # noqa: BLE001
                self._event("mint_failed", detail=f"{type(exc).__name__}: {exc}")
                logs.log.warning("enigma %s: minting a key failed (%s); retrying in %.0f s", self.name, type(exc).__name__, delay)
                wait = delay
            await self.clock.sleep(min(wait, 300.0))
            delay = min(delay * 2, 60.0)

    async def _mint_and_validate(self) -> KeyRecord:
        self._seq += 1
        label = f"enigma-{self._seq:03d}"
        expires_at = self.clock.utcnow() + timedelta(seconds=self.policy.ttl_seconds)
        minted = await self.backend.mint(suffix=f"{self._run_id}-{self._seq}", expires_at=expires_at,
                                         limit_usd=self.policy.per_key_limit_usd)
        record = KeyRecord(minted=minted, label=label, state=VALIDATING, minted_at=self.clock.monotonic())
        with self._lock:
            self._records.append(record)      # a secret from this moment on, even before it is used
        self._event("minted", record)
        try:
            valid = await self._validate(record)
        except asyncio.CancelledError:
            record.state = DISCARDED
            self._spawn(self._revoke(record, settle=False))
            raise
        if not valid:
            record.state = DISCARDED
            self._event("validation_failed", record)
            self._spawn(self._revoke(record, settle=False))
            raise CustodyError(f"new key {label} did not validate within {self.policy.validate_window_seconds:.0f} s; discarded")
        record.state = STANDBY
        return record

    async def _validate(self, record: KeyRecord) -> bool:
        started, delay = self.clock.monotonic(), 0.5
        while True:
            try:
                if await self.probe(record.minted.key):
                    return True
            except CustodyError:
                pass   # an unclear answer: try again within the window
            if self.clock.monotonic() - started + delay > self.policy.validate_window_seconds:
                return False
            await self.clock.sleep(delay)
            delay = min(delay * 2, 4.0)

    # ---------- drain and revoke ----------
    async def _drain_and_revoke(self, record: KeyRecord) -> None:
        self._event("draining", record, detail=f"{record.refcount} open lease(s)")
        if record.refcount > 0:
            idle = asyncio.ensure_future(record.idle.wait())
            cap = asyncio.ensure_future(self.clock.sleep(self.policy.drain_cap_seconds))
            try:
                await asyncio.wait({idle, cap}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                idle.cancel()
                cap.cancel()
        with self._lock:
            record.forced = record.refcount > 0
            record.state = REVOKING
        if record.forced:
            self._event("drain_cap_reached", record, detail=f"{record.refcount} lease(s) still open")
            logs.log.warning("enigma %s: %s still had %d open lease(s) at the drain cap; revoking anyway",
                             self.name, record.label, record.refcount)
        await self._revoke(record, settle=True)

    async def _revoke(self, record: KeyRecord, *, settle: bool, confirm: bool = True) -> None:
        if settle and self.policy.settle_seconds:
            await self.clock.sleep(self.policy.settle_seconds)
        if settle:
            try:
                record.usage_usd = await self.backend.usage(record.minted.hash)
                self.spend_usd += record.usage_usd
            except Exception:   # noqa: BLE001 - the ledger is approximate; OpenRouter's activity page is authoritative
                pass
        try:
            record.revoke_outcome = await self.backend.revoke(record.minted.hash)
        except Exception as exc:   # noqa: BLE001
            record.state = REVOKE_FAILED
            self._event("revoke_failed", record, detail=str(exc))
            logs.log.error("enigma %s: could not revoke %s (%s); it dies at its expires_at", self.name, record.label, record.short_hash)
            return
        record.state = REVOKED
        record.revoked_at = self.clock.monotonic()
        self._event("revoked", record, detail=record.revoke_outcome or "")
        if confirm:
            await self._confirm_dead(record)

    async def _confirm_dead(self, record: KeyRecord) -> None:
        """Probe until the key answers 401: the time from revocation to then is the propagation delay (§4)."""
        while True:
            try:
                alive = await self.probe(record.minted.key)
            except Exception:   # noqa: BLE001 - unknown counts as still alive
                alive = True
            if not alive:
                record.dead_at = self.clock.monotonic()
                delay = record.dead_at - record.revoked_at
                self.propagation_seconds.append(delay)
                self._forget(record, DEAD)
                self._event("dead", record, detail=f"{delay:.1f} s after revocation")
                return
            if self.clock.monotonic() - record.revoked_at >= self.policy.confirm_window_seconds:
                self._event("revocation_unconfirmed", record)
                logs.log.warning("enigma %s: %s still works %.0f s after revocation; it dies at its expires_at",
                                 self.name, record.label, self.policy.confirm_window_seconds)
                return
            await self.clock.sleep(self.policy.confirm_every_seconds)

    def _forget(self, record: KeyRecord, state: str) -> None:
        with self._lock:
            record.state = state
            if record in self._records:
                self._records.remove(record)
        self.history.append(record)

    def _prune(self) -> None:
        """Forget keys past expires_at with no open lease: OpenRouter has killed them, whatever our revoke did."""
        now = self.clock.utcnow()
        with self._lock:
            expired = [r for r in self._records if r.minted.expires_at <= now and r.refcount <= 0
                       and r is not self._active and r is not self._standby]
        for record in expired:
            self._forget(record, record.state)

    # ---------- bookkeeping ----------
    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _event(self, kind: str, record: KeyRecord | None = None, detail: str = "") -> None:
        event: dict[str, Any] = {"at": round(self.clock.monotonic(), 3), "type": kind}
        if record is not None:
            event.update(label=record.label, hash=record.short_hash)
        if detail:
            event["detail"] = logs_safe(detail)
        self.events.append(event)

    def snapshot(self) -> dict[str, Any]:
        """For the status API (step 5): labels, states and times only. No key values, no full hashes."""
        now = self.clock.monotonic()
        with self._lock:
            records = list(self._records)
            active = self._active
        return {
            "provider": self.name,
            "active": active.label if active else None,
            "keys": [{"label": r.label, "hash": r.short_hash, "state": r.state, "refcount": r.refcount,
                      "expires_at": r.minted.expires_at.isoformat(),
                      "seconds_left": round(max(0.0, r.deadline - now), 1) if r.state == ACTIVE else None}
                     for r in records],
            "spend_usd": round(self.spend_usd, 6),
            "propagation_seconds": list(self.propagation_seconds),
            "events": list(self.events),
        }


_KEYISH = re.compile(r"sk-[A-Za-z0-9_-]{8,}")


def logs_safe(text: str) -> str:
    return _KEYISH.sub("<redacted>", text)[:200]
