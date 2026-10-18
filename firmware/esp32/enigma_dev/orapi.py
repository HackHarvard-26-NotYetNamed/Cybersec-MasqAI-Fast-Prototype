"""OpenRouter management calls made by the device itself (design §3.2, §13.5).

The board supplies `https(method, path, bearer, body) -> (status, headers, body)` over a verified TLS connection to
openrouter.ai, and raises `ApiError` for network and TLS failures. This module adds JSON, error mapping, and the
server clock: every response's `Date` header (authenticated by TLS) updates `server_time`, which is the only clock
used for key expiry and rate limits.
"""
import json

from .timeutil import parse_http_date

BASE = "/api/v1"
HEX = "0123456789abcdef"


class ApiError(Exception):
    """code: MGMT_AUTH, NOT_FOUND, RATE_LIMITED, BAD_REQUEST, UPSTREAM, NETWORK, TLS_VERIFY_FAILED, RESP_TOO_LARGE,
    BAD_RESPONSE. `sent` is False only when the request certainly never reached OpenRouter."""

    def __init__(self, code, msg="", status=0, sent=True):
        super().__init__(code + (": " + msg if msg else ""))
        self.code = code
        self.msg = msg
        self.status = status
        self.sent = sent


def is_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in HEX for c in value)


def is_uuid(value):
    if not isinstance(value, str) or len(value) != 36:
        return False
    for i, c in enumerate(value):
        if i in (8, 13, 18, 23):
            if c != "-":
                return False
        elif c not in HEX:
            return False
    return True


def cents_text(cents):
    return "%d.%02d" % (cents // 100, cents % 100)


def to_cents(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value * 100 + 0.5)


class OpenRouterApi:
    SYNC_MAX_AGE = 3600   # re-read the server clock at least this often before minting

    def __init__(self, board):
        self.board = board
        self.server_time = None
        self.seen_at = 0

    def now(self):
        """OpenRouter's clock, extrapolated with the board's monotonic clock; None if never seen."""
        if self.server_time is None:
            return None
        return self.server_time + (self.board.ticks_s() - self.seen_at)

    def fresh(self):
        return self.server_time is not None and self.board.ticks_s() - self.seen_at < self.SYNC_MAX_AGE

    def call(self, method, path, key, body=None):
        status, headers, raw = self.board.https(method, BASE + path, key, body)
        when = parse_http_date(headers.get("date", ""))
        if when is not None:
            self.server_time = when
            self.seen_at = self.board.ticks_s()
        data = None
        if raw:
            try:
                data = json.loads(raw)
            except ValueError:
                data = None
        if 200 <= status < 300:
            if data is None and method != "DELETE":
                raise ApiError("BAD_RESPONSE", "not JSON", status)
            return data
        if status in (401, 403):
            raise ApiError("MGMT_AUTH", "management key refused", status)
        if status == 404:
            raise ApiError("NOT_FOUND", "", status)
        if status == 429:
            raise ApiError("RATE_LIMITED", "", status)
        if 400 <= status < 500:
            raise ApiError("BAD_REQUEST", "HTTP %d" % status, status)
        raise ApiError("UPSTREAM", "HTTP %d" % status, status)

    @staticmethod
    def _data(payload):
        if not isinstance(payload, dict) or "data" not in payload:
            raise ApiError("BAD_RESPONSE", "no data")
        return payload["data"]

    def whoami(self, key):
        data = self._data(self.call("GET", "/key", key))
        return data if isinstance(data, dict) else {}

    def workspace(self, key, workspace_id):
        return self._data(self.call("GET", "/workspaces/" + workspace_id, key))

    def budgets(self, key, workspace_id):
        data = self._data(self.call("GET", "/workspaces/" + workspace_id + "/budgets", key))
        return [b for b in data if isinstance(b, dict)] if isinstance(data, list) else []

    def create(self, key, name, workspace_id, limit_cents, expires_iso):
        body = '{"name": %s, "workspace_id": %s, "limit": %s, "limit_reset": null, "include_byok_in_limit": true, ' \
               '"expires_at": %s}' % (json.dumps(name), json.dumps(workspace_id), cents_text(limit_cents), json.dumps(expires_iso))
        payload = self.call("POST", "/keys", key, body.encode())
        if not isinstance(payload, dict) or not isinstance(payload.get("key"), str) or not isinstance(payload.get("data"), dict):
            raise ApiError("BAD_RESPONSE", "create response lacks the key or its data")
        return payload

    def get(self, key, key_hash):
        data = self._data(self.call("GET", "/keys/" + key_hash, key))
        return data if isinstance(data, dict) else {}

    def delete(self, key, key_hash):
        self.call("DELETE", "/keys/" + key_hash, key)

    def disable(self, key, key_hash):
        self.call("PATCH", "/keys/" + key_hash, key, b'{"disabled": true}')
