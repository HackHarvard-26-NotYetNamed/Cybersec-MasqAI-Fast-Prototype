"""Firmware policy (design §13.5): fixed at enrollment, enforced on every MINT. The host cannot change it.

Rate limits are computed from the journal (persisted in flash) and the server clock (OpenRouter's TLS-authenticated
`Date` header), so a device reboot does not reset them and the host cannot stretch them by lying about time.
"""

# Units: cents for money (no floats on the wire: the ESP32 port has single-precision floats), seconds for time.
DEFAULTS = {
    "max_limit_c": 200,          # $2.00 per key
    "max_ttl_s": 1900,           # about 31.7 min (§5)
    "min_mint_gap_s": 240,       # normal rotation is at least 300 s minus jitter
    "burst_max": 3,              # mints closer together than the gap: at most 3 ...
    "burst_window_s": 600,       # ... per 10 min (the 401/limit emergency path, §8)
    "max_mints_per_day": 120,
    "max_live_keys": 4,          # active + standby + draining, with slack
}
# Sanity bounds for enrollment overrides. Enrollment is a trusted, physically present act; these only stop typos.
BOUNDS = {
    "max_limit_c": (1, 10000),
    "max_ttl_s": (300, 86400),
    "min_mint_gap_s": (60, 3600),
    "burst_max": (0, 10),
    "burst_window_s": (60, 3600),
    "max_mints_per_day": (1, 1000),
    "max_live_keys": (2, 16),
}
DAY = 86400
LIVE_STATES = ("pending", "live", "failed")


class PolicyError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def build(overrides=None):
    """Defaults plus validated overrides. Unknown names are refused (a typo must not silently keep a default)."""
    policy = dict(DEFAULTS)
    for name in (overrides or {}):
        if name not in BOUNDS:
            raise PolicyError("BAD_ARGS", "unknown policy field %s" % name)
        value = overrides[name]
        low, high = BOUNDS[name]
        if not _is_int(value) or not low <= value <= high:
            raise PolicyError("BAD_ARGS", "policy %s must be an integer in %d..%d" % (name, low, high))
        policy[name] = value
    return policy


def check(policy):
    """A policy read back from flash must still be complete and in bounds."""
    if not isinstance(policy, dict) or sorted(policy) != sorted(DEFAULTS):
        raise PolicyError("CORRUPT", "stored policy is incomplete")
    build(policy)
    return policy


def live_count(entries, now):
    return len([e for e in entries if e["st"] in LIVE_STATES and e["x"] > now])


def counts(policy, entries, now):
    minted = [e for e in entries if e["c"] > now - DAY]
    burst = [e for e in entries if e.get("b") and e["c"] > now - policy["burst_window_s"]]
    return {"live": live_count(entries, now), "minted_24h": len(minted), "burst_window": len(burst)}


def admit(policy, entries, now, ttl, limit_c):
    """Raise PolicyError if a mint is not allowed now; return (ttl, burst) for an allowed one.

    `entries` are journal entries: {"c": created, "x": expires_at, "st": state, "b": 1 if burst}. A requested ttl
    above the cap is refused rather than silently shortened, so a misconfigured gateway fails at startup."""
    if not _is_int(ttl) or ttl < 60:
        raise PolicyError("BAD_ARGS", "ttl must be an integer of at least 60 s")
    if ttl > policy["max_ttl_s"]:
        raise PolicyError("POLICY_TTL", "ttl %d s exceeds the device cap of %d s" % (ttl, policy["max_ttl_s"]))
    if not _is_int(limit_c) or limit_c < 1:
        raise PolicyError("BAD_ARGS", "limit must be a positive number of cents")
    if limit_c > policy["max_limit_c"]:
        raise PolicyError("POLICY_LIMIT", "limit %d cents exceeds the device cap of %d" % (limit_c, policy["max_limit_c"]))
    if live_count(entries, now) >= policy["max_live_keys"]:
        raise PolicyError("LIVE_KEYS", "%d keys are still live (cap %d)" % (live_count(entries, now), policy["max_live_keys"]))
    c = counts(policy, entries, now)
    if c["minted_24h"] >= policy["max_mints_per_day"]:
        raise PolicyError("RATE_DAY", "%d mints in the last 24 h (cap %d)" % (c["minted_24h"], policy["max_mints_per_day"]))
    last = 0
    for e in entries:
        if e["c"] > last:
            last = e["c"]
    burst = 0
    if last and now - last < policy["min_mint_gap_s"]:
        if c["burst_window"] >= policy["burst_max"]:
            raise PolicyError("RATE_GAP", "minted %d s ago and the burst allowance (%d per %d s) is used up"
                              % (now - last, policy["burst_max"], policy["burst_window_s"]))
        burst = 1
    return ttl, burst
