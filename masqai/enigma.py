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

    def rotates(self, name: str) -> bool:
        return name in self._sources

    def lease(self, provider: ProviderConfig) -> KeyLease:
        return self.source(provider).lease()

    def known_secrets(self) -> list[tuple[str, str]]:
        return [secret for source in self._sources.values() for secret in source.known_secrets()]

    def report_rejected(self, provider: ProviderConfig, key: str | None, reason: str) -> bool:
        """Forward an upstream rejection to the provider's rotating source. False if there is none."""
        source = self._sources.get(provider.name)
        report = getattr(source, "report_rejected", None)
        return bool(report and report(key, reason))

    def status(self) -> list[dict[str, Any]]:
        return [source.snapshot() for source in self._sources.values() if hasattr(source, "snapshot")]

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
    # "closed" (default): no validated key -> 503. "open": keep using the current key past its interval while minting
    # retries, but never past its own expires_at minus the drain and skew margin; then it is closed again (§8).
    failure_policy: str = "closed"
    emergency_max: float = 3                # emergency rotations (401 / key limit) allowed per window
    emergency_window_seconds: float = 600.0

    def __post_init__(self) -> None:
        if self.failure_policy not in ("closed", "open"):
            raise ValueError("failure_policy must be 'closed' or 'open'")
        numbers = {k: v for k, v in vars(self).items() if k != "failure_policy"}
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in numbers.values()):
            raise ValueError("rotation policy values must be finite numbers")
        if self.emergency_max < 0 or self.emergency_window_seconds <= 0:
            raise ValueError("emergency_max must not be negative and emergency_window_seconds must be positive")
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
    condemned: str = ""                   # why it must stop now: "revoked_externally" / "key_limit"
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
                 clock: Clock | None = None, probe: Probe | None = None, rng: Any = None, owns_backend: bool = False) -> None:
        self.name = name
        self.backend = backend
        self.owns_backend = owns_backend             # close (and wipe) the backend when the source stops
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
        self._emergencies: deque[float] = deque()
        self._cooldown_until = 0.0
        self._wake = asyncio.Event()                 # set by report_rejected: mint now instead of on schedule
        self.cleaned_up = 0
        self.management_expires_at: datetime | None = None
        self._expiry_warned: set[str] = set()

    # ---------- leases: synchronous, on the request path ----------
    def lease(self) -> KeyLease:
        retired = None
        with self._lock:
            if self._stopped or self._active is None:
                raise KeyUnavailable(f"no validated key for {self.name} (fail closed)")
            if self.clock.monotonic() >= self._active.deadline and not self._may_overstay_locked(self._active):
                retired = self._swap_locked()
                if self._active is None:
                    self._after_swap(retired)
                    raise KeyUnavailable(f"the key interval for {self.name} ended without a validated successor (fail closed)")
            record = self._active
            record.refcount += 1
        if retired is not None:
            self._after_swap(retired)
        return KeyLease(record.minted.key, lambda: self._release(record))

    def hard_deadline(self, record: KeyRecord) -> float:
        """Monotonic time after which a key must take no new lease under any policy: expires_at - drain - margin."""
        left = ((record.minted.expires_at - self.clock.utcnow()).total_seconds()
                - self.policy.drain_cap_seconds - self.policy.safety_margin_seconds)
        return self.clock.monotonic() + max(0.0, left)

    def _may_overstay_locked(self, record: KeyRecord) -> bool:
        """failure_policy "open": past its interval, with no successor ready, a healthy key keeps serving until its
        hard deadline. A revoked or exhausted key (marked `condemned`) never overstays."""
        return (self.policy.failure_policy == "open" and self._standby is None and not record.condemned
                and self.clock.monotonic() < self.hard_deadline(record))

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
            if active is None and not retired.condemned:
                self._event("interval_ended_without_successor", retired)
                logs.log.error("enigma %s: %s retired with no validated successor; refusing requests (fail closed)",
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
        """Every key value that may still work: active, standby, draining, and revoked but not confirmed dead. Plus
        the backend's own secret (passphrase mode: the management key, as ADMIN_KEY)."""
        now = self.clock.utcnow()
        own = getattr(self.backend, "known_secrets", None)
        with self._lock:
            keys = [(r.minted.key, self.SECRET_TYPE) for r in self._records if r.minted.expires_at > now]
        return (own() if own else []) + keys

    @property
    def active(self) -> KeyRecord | None:
        return self._active

    # ---------- emergency rotation (§8) ----------
    def report_rejected(self, key: str | None, reason: str) -> bool:
        """The upstream refused `key`: 401 (revoked or expired: `revoked_externally`) or 402/403 with
        limit_source openrouter_key_limit (`key_limit`). Retire it now and wake the rotation task.

        Returns True if a different validated key can be leased right away, so the caller may retry once. Emergency
        rotations are capped (emergency_max per emergency_window_seconds); past the cap, the key is still retired,
        but no early mint is triggered, so an attacker forcing 401s can't make us mint in a loop.
        """
        if reason not in ("revoked_externally", "key_limit"):
            raise ValueError(f"unknown rejection reason {reason!r}")
        retired = None
        with self._lock:
            record = self._active
            if record is None or key is None or record.minted.key != key:
                # A stale report about an already retired key, or an unrelated value: nothing to do.
                return self._active is not None and self._active.minted.key != key
            record.condemned = reason
            now = self.clock.monotonic()
            while self._emergencies and now - self._emergencies[0] >= self.policy.emergency_window_seconds:
                self._emergencies.popleft()
            allowed = len(self._emergencies) < self.policy.emergency_max
            if allowed:
                self._emergencies.append(now)
            else:
                # Past the cap: the next early mint waits until the oldest emergency leaves the window.
                self._cooldown_until = self._emergencies[0] + self.policy.emergency_window_seconds
            retired = self._swap_locked()
            ready = self._active is not None
        self._event(reason, retired, detail="emergency rotation" if allowed else "emergency rotation cap reached")
        log = logs.log.warning if reason == "key_limit" else logs.log.error
        log("enigma %s: upstream rejected %s (%s)%s", self.name, retired.label, reason,
            "" if allowed else "; emergency rotation cap reached, refusing requests until the cap window passes")
        self._after_swap(retired)
        self._call_on_loop(self._wake.set)
        return ready

    # ---------- lifecycle ----------
    async def start(self, attempts: int = 3) -> None:
        """Before the gateway accepts traffic: delete this install's leftover keys from earlier runs (they can't be
        used: a key value is shown once), then obtain and activate the first key. Raises KeyUnavailable on failure.

        Cleanup runs before the first mint, so it can never delete a key of this run. A failed cleanup is logged and
        does not block startup: leftovers die at their own expires_at anyway (§6).
        """
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        # The management key must be a management key, and the workspace must exist and have a budget (owner
        # decision, §7). Checked before anything is created.
        try:
            status = await self.backend.status()
        except Exception as exc:   # noqa: BLE001
            raise KeyUnavailable(f"could not check the key backend for {self.name}: {type(exc).__name__}: {logs_safe(str(exc))}") from None
        if not status.healthy:
            self._event("backend_unhealthy", detail=status.detail)
            raise KeyUnavailable(f"the key backend for {self.name} is not ready: {logs_safe(status.detail)}")
        self.management_expires_at = status.management_expires_at
        self._check_management_expiry()
        try:
            self.cleaned_up = await self.backend.cleanup()
            self._event("cleanup", detail=f"{self.cleaned_up} leftover key(s) revoked")
        except ManagementAuthError as exc:
            self._event("management_key_refused", detail=str(exc))
            raise KeyUnavailable(f"the management key was refused for {self.name}: {logs_safe(str(exc))}") from None
        except Exception as exc:   # noqa: BLE001
            self._event("cleanup_failed", detail=f"{type(exc).__name__}: {exc}")
            logs.log.warning("enigma %s: startup cleanup failed (%s); leftovers die at their expires_at", self.name, type(exc).__name__)
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

    def _check_management_expiry(self) -> None:
        """Warn once at 7 days and once at 1 day before the management key expires (§3.3)."""
        expires = self.management_expires_at
        if expires is None:
            return
        left = (expires - self.clock.utcnow()).total_seconds()
        for mark, seconds in (("1d", 86400.0), ("7d", 7 * 86400.0)):
            if left <= seconds:
                if mark not in self._expiry_warned:
                    self._expiry_warned.update({"1d", "7d"} if mark == "1d" else {"7d"})
                    detail = "expired" if left <= 0 else f"expires in {left / 3600:.0f} h"
                    self._event("management_key_expiring", detail=detail)
                    logs.log.warning("enigma %s: the management key %s; create a new one and re-seal (python -m masqai.vault)",
                                     self.name, detail)
                return

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
        if self.owns_backend:
            # Passphrase mode: closes the management client and wipes the management key's bytearray.
            try:
                await self.backend.aclose()
            except Exception:   # noqa: BLE001
                logs.log.warning("enigma %s: closing the key backend failed", self.name)

    # ---------- the rotation loop ----------
    async def _run(self) -> None:
        try:
            while not self._stopped:
                current = self._active
                if current is None:
                    self._wake.clear()
                    await self._sleep_until(self._cooldown_until)   # after a capped emergency storm
                    successor = await self._obtain()            # fail-closed gap: recover as soon as possible
                    with self._lock:
                        if not self._stopped and self._active is None:
                            self._start_interval_locked(successor)
                            successor = None
                    if successor is not None:                  # stopped, or recovered meanwhile: not needed
                        self._spawn(self._revoke(successor, settle=False))
                    self._after_swap(None)
                    continue
                if not await self._sleep_or_wake(current.deadline - self.policy.lead_seconds):
                    continue                                    # emergency: the active key changed
                # Under "open", keep looking for a successor until the hard deadline, not only the interval end.
                limit = current.deadline if self.policy.failure_policy == "closed" else max(current.deadline, self.hard_deadline(current))
                successor = await self._obtain_before(limit)
                if successor is not None:
                    with self._lock:
                        if self._active is current and not self._stopped:
                            self._standby = successor
                            successor = None
                    if successor is not None:                  # replaced or stopped meanwhile: never needed
                        self._spawn(self._revoke(successor, settle=False))
                        continue
                    await self._sleep_or_wake(current.deadline)
                retired = None
                with self._lock:
                    if self._active is current:                 # a lease or an emergency may already have swapped
                        retired = self._swap_locked()
                self._after_swap(retired)
                self._prune()
                self._check_management_expiry()
        except asyncio.CancelledError:
            raise
        except Exception:   # noqa: BLE001 - leases still stop at the deadline
            logs.log.exception("enigma %s: rotation loop crashed; requests stop when the current interval ends", self.name)
            self._event("rotation_crashed")

    async def _sleep_or_wake(self, when: float) -> bool:
        """Sleep until `when`. Returns False early if an emergency rotation woke the loop."""
        if self._wake.is_set():
            self._wake.clear()
            return False
        sleeper = asyncio.ensure_future(self._sleep_until(when))
        waker = asyncio.ensure_future(self._wake.wait())
        try:
            await asyncio.wait({sleeper, waker}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            sleeper.cancel()
            waker.cancel()
        if self._wake.is_set():
            self._wake.clear()
            return False
        return True

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
        # A key revoked behind our back may have leaked: don't wait for its streams. (They are failing anyway.)
        if record.refcount > 0 and record.condemned != "revoked_externally":
            idle = asyncio.ensure_future(record.idle.wait())
            cap = asyncio.ensure_future(self.clock.sleep(self.policy.drain_cap_seconds))
            try:
                await asyncio.wait({idle, cap}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                idle.cancel()
                cap.cancel()
        with self._lock:
            record.forced = record.refcount > 0 and record.condemned != "revoked_externally"
            record.state = REVOKING
        if record.forced:
            self._event("drain_cap_reached", record, detail=f"{record.refcount} lease(s) still open")
            logs.log.warning("enigma %s: %s still had %d open lease(s) at the drain cap; revoking anyway",
                             self.name, record.label, record.refcount)
        # A rejected key gets no settle wait: revoke it at once, but still read its usage for the ledger.
        await self._revoke(record, settle=True, wait=not record.condemned)

    async def _revoke(self, record: KeyRecord, *, settle: bool, confirm: bool = True, wait: bool = True) -> None:
        if settle and wait and self.policy.settle_seconds:
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
        """For GET /api/enigma/status: labels, states and times only. No key values, no full hashes."""
        now = self.clock.monotonic()
        with self._lock:
            records = list(self._records)
            active = self._active
            stopped = self._stopped
        delays = sorted(self.propagation_seconds)
        return {
            "provider": self.name,
            "running": not stopped,
            "failure_policy": self.policy.failure_policy,
            "interval_seconds": self.policy.interval_seconds,
            "per_key_limit_usd": self.policy.per_key_limit_usd,
            "active": active.label if active else None,
            "keys": [{"label": r.label, "hash": r.short_hash, "state": r.state, "refcount": r.refcount,
                      "expires_at": r.minted.expires_at.isoformat(), **({"condemned": r.condemned} if r.condemned else {}),
                      "seconds_left": round(max(0.0, r.deadline - now), 1) if r.state == ACTIVE else None}
                     for r in records],
            "spend_usd": round(self.spend_usd, 6),
            "spend_note": "approximate; OpenRouter's activity page is authoritative",
            "propagation_seconds": ({"count": len(delays), "min": delays[0], "median": delays[len(delays) // 2], "max": delays[-1]}
                                    if delays else {"count": 0}),
            "cleaned_up": self.cleaned_up,
            "custody": getattr(self.backend, "mode", None),
            "management_expires_at": self.management_expires_at.isoformat() if self.management_expires_at else None,
            "events": list(self.events),
        }


_KEYISH = re.compile(r"sk-[A-Za-z0-9_-]{8,}")


def policy_for(provider: ProviderConfig, upstream_timeout_seconds: float) -> RotationPolicy:
    """The rotation policy for a provider's key_enigma block. The drain cap defaults to the upstream timeout."""
    enigma = provider.key_enigma
    if enigma is None:
        raise ValueError(f"provider {provider.name!r} has no key_enigma block")
    return RotationPolicy(interval_seconds=enigma.interval_seconds, jitter=enigma.jitter,
                          drain_cap_seconds=enigma.drain_cap_seconds or upstream_timeout_seconds,
                          per_key_limit_usd=enigma.per_key_limit_usd, failure_policy=enigma.failure_policy)


def build_keyring(config: Any, backends: dict[str, ManagementBackend], **source_options: Any) -> KeyRing:
    """One EnigmaKeySource per provider with key_enigma enabled, on the backend opened for it (run_gateway opens
    them before uvicorn starts). The sources own their backends: stopping one closes it (and wipes the key)."""
    sources: dict[str, KeySource] = {}
    for provider in config.providers:
        if not provider.rotates:
            continue
        if provider.name not in backends:
            raise ValueError(f"no key backend was opened for provider {provider.name!r}")
        sources[provider.name] = EnigmaKeySource(provider.name, backends[provider.name],
                                                 policy_for(provider, config.upstream_timeout_seconds),
                                                 owns_backend=True, **source_options)
    return KeyRing(sources)


def rejection_reason(status: int, body: bytes) -> str | None:
    """Does this upstream answer mean *our key* is unusable (§8)? 401 -> revoked or expired. 402/403 with
    limit_source openrouter_key_limit -> its spend limit is used up. Everything else (credits, in-flight budget,
    guardrails, workspace budget) passes through unchanged: rotating would not help."""
    if status == 401:
        return "revoked_externally"
    if status in (402, 403):
        try:
            import json
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return None
        error = data.get("error") if isinstance(data, dict) else None
        metadata = error.get("metadata") if isinstance(error, dict) else None
        sources = {data.get("limit_source") if isinstance(data, dict) else None,
                   error.get("limit_source") if isinstance(error, dict) else None,
                   metadata.get("limit_source") if isinstance(metadata, dict) else None}
        if "openrouter_key_limit" in sources:
            return "key_limit"
    return None


def logs_safe(text: str) -> str:
    return _KEYISH.sub("<redacted>", text)[:200]
