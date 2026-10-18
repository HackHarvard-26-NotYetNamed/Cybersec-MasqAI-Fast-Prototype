"""The device's journal of minted keys (design §6, §8): hashes, names, times and states. No key values.

One JSON list per line in a single flash file: [hash or null, suffix, created, expires_at, state, burst]. The file is
rewritten whole on every change (it is small: about a day of keys), via the board's atomic write.

States: pending (POST sent, no answer yet: the key may exist), live, failed (revoke failed; dies at expires_at),
revoked (deleted, disabled or already gone).
"""
import json

from .policy import DAY, LIVE_STATES

MAX_ENTRIES = 400
STATES = ("pending", "live", "failed", "revoked")


class Journal:
    def __init__(self, board, name="journal"):
        self.board = board
        self.name = name
        self.entries = []
        self.load()

    def load(self):
        self.entries = []
        raw = self.board.read(self.name)
        if not raw:
            return
        for line in raw.split(b"\n"):
            if not line.strip():
                continue
            try:
                h, s, c, x, st, b = json.loads(line)
            except (ValueError, TypeError):
                continue   # a torn line: skip it (its key dies at expires_at)
            if st in STATES and isinstance(c, int) and isinstance(x, int):
                self.entries.append({"h": h, "s": s, "c": c, "x": x, "st": st, "b": 1 if b else 0})

    def save(self):
        lines = [json.dumps([e["h"], e["s"], e["c"], e["x"], e["st"], e["b"]]) for e in self.entries]
        self.board.write(self.name, ("\n".join(lines) + "\n").encode())

    def add(self, suffix, created, expires, burst):
        entry = {"h": None, "s": suffix, "c": created, "x": expires, "st": "pending", "b": burst}
        self.entries.append(entry)
        self.save()
        return entry

    def find(self, key_hash):
        for e in self.entries:
            if e["h"] == key_hash:
                return e
        return None

    def drop(self, entry):
        if entry in self.entries:
            self.entries.remove(entry)
            self.save()

    def set(self, entry, **changes):
        for k in changes:
            entry[k] = changes[k]
        self.save()

    def open_entries(self):
        """Entries that may still be a working key and that we can name to OpenRouter."""
        return [e for e in self.entries if e["st"] in LIVE_STATES and e["h"]]

    def prune(self, now):
        """Forget entries older than a day that can no longer be live. Their creation time no longer counts toward
        the daily cap, and OpenRouter has killed them at expires_at."""
        keep = [e for e in self.entries if e["c"] > now - DAY or (e["st"] in LIVE_STATES and e["x"] > now)]
        if len(keep) > MAX_ENTRIES:
            keep = keep[-MAX_ENTRIES:]
        if len(keep) != len(self.entries):
            self.entries = keep
            self.save()
