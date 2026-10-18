"""The passphrase vault for the OpenRouter management key (design: KeyEnigma.OpenRouter.doc.md §3.1).

The vault is one JSON object:

    {"v": 1, "kdf": "argon2id", "m_kib": 262144, "t": 3, "p": 4, "salt": "<b64>", "nonce": "<b64>",
     "provider": "openrouter", "created": "...Z", "management_expires_at": "...Z" | null, "hint": "...",
     "ct": "<AES-256-GCM ciphertext + tag, b64>"}

- key = Argon2id(passphrase, salt, m, t, p) -> 32 bytes; plaintext = the management key (UTF-8).
- Every field except `ct` is bound into the encryption as associated data, so changing any of them (for example
  lowering `m_kib` to make guessing cheaper, or moving the stated expiry) makes decryption fail.
- The field set is exact and the Argon2 cost has a floor and a ceiling, checked before any work is done.
- Fresh salt and nonce on every seal. Written atomically, owner-only (best effort: the encryption is the protection).

CLI: python -m masqai.vault seal | verify | repass | destroy [--path PATH]. Secrets are read with getpass only,
never from arguments or environment variables, and are never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import getpass
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import CustodyError, ManagementAuthError

VERSION = 1
KDF = "argon2id"
DEFAULT_COST = {"m_kib": 262144, "t": 3, "p": 4}     # 256 MiB, 3 passes, 4 lanes (stronger than RFC 9106's 64 MiB)
MIN_M_KIB, MAX_M_KIB = 65536, 1048576                 # 64 MiB floor (RFC 9106 second recommendation), 1 GiB ceiling
MAX_T, MAX_P = 10, 16
MIN_PASSPHRASE = 14
MAX_FILE_BYTES = 64 * 1024
MAX_SECRET_BYTES = 4096
FIELDS = frozenset({"v", "kdf", "m_kib", "t", "p", "salt", "nonce", "provider", "created", "management_expires_at", "hint", "ct"})
PROVIDERS = ("openrouter",)


def default_path() -> Path:
    return Path.home() / ".masqai" / "openrouter.vault"


class VaultError(CustodyError):
    """The vault file is missing, malformed, or refused. Messages never contain the passphrase or the key."""


class WrongPassphrase(VaultError):
    """Decryption failed: the passphrase is wrong, or the file was modified (AES-GCM can't tell the two apart)."""


# ---------------------------------------------------------------------------------------------------------------
# The decrypted secret
# ---------------------------------------------------------------------------------------------------------------

class Unsealed:
    """The management key in a bytearray, wiped by wipe(). Python may still hold copies elsewhere (the str handed to
    httpx, header buffers), so the guarantee is "only in RAM", not "erased from RAM" (§3.1)."""

    __slots__ = ("_buf", "provider", "management_expires_at", "hint")

    def __init__(self, secret: bytes | bytearray, *, provider: str, management_expires_at: datetime | None, hint: str) -> None:
        self._buf = bytearray(secret)
        self.provider = provider
        self.management_expires_at = management_expires_at
        self.hint = hint

    @property
    def wiped(self) -> bool:
        return not self._buf

    def reveal(self) -> str:
        if not self._buf:
            raise VaultError("the management key was wiped")
        return self._buf.decode("utf-8")

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf.clear()

    def __repr__(self) -> str:
        return f"Unsealed({self.provider}, <hidden>{', wiped' if self.wiped else ''})"


# ---------------------------------------------------------------------------------------------------------------
# Format
# ---------------------------------------------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any, name: str) -> bytes:
    if not isinstance(value, str):
        raise VaultError(f"vault field {name!r} must be base64 text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise VaultError(f"vault field {name!r} is not valid base64") from None


def _iso(when: datetime | None) -> str | None:
    if when is None:
        return None
    if when.tzinfo is None:
        raise VaultError("management_expires_at must be timezone-aware")
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise VaultError("vault field 'management_expires_at' must be a timestamp or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise VaultError("vault field 'management_expires_at' is not a timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _aad(header: dict[str, Any]) -> bytes:
    """Every field except the ciphertext, canonically encoded."""
    return json.dumps({k: v for k, v in header.items() if k != "ct"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _check_cost(m_kib: Any, t: Any, p: Any) -> None:
    for name, value in (("m_kib", m_kib), ("t", t), ("p", p)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise VaultError(f"vault field {name!r} must be an integer")
    if not MIN_M_KIB <= m_kib <= MAX_M_KIB:
        raise VaultError(f"Argon2 memory must be between {MIN_M_KIB} and {MAX_M_KIB} KiB (got {m_kib})")
    if not 1 <= t <= MAX_T or not 1 <= p <= MAX_P:
        raise VaultError(f"Argon2 passes must be 1-{MAX_T} and lanes 1-{MAX_P}")
    if m_kib < 8 * p:
        raise VaultError("Argon2 memory must be at least 8 KiB per lane")


def _derive(passphrase: str, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    from argon2.low_level import Type, hash_secret_raw
    secret = unicodedata.normalize("NFC", passphrase).encode("utf-8")
    return hash_secret_raw(secret, salt, time_cost=t, memory_cost=m_kib, parallelism=p, hash_len=32, type=Type.ID)


def check_passphrase(passphrase: str, management_key: str) -> None:
    """At least 14 characters, and not related to the key it protects."""
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise VaultError(f"the passphrase must be at least {MIN_PASSPHRASE} characters")
    if management_key and (management_key in passphrase or passphrase in management_key):
        raise VaultError("the passphrase must not contain the management key (or be part of it)")


def check_management_key(key: str) -> None:
    if not isinstance(key, str) or not key.strip():
        raise VaultError("no management key given")
    if key != key.strip() or any(c.isspace() for c in key):
        raise VaultError("the management key must not contain whitespace")
    if len(key.encode("utf-8")) > MAX_SECRET_BYTES:
        raise VaultError("the management key is too long")


def seal_bytes(management_key: str, passphrase: str, *, provider: str = "openrouter",
               management_expires_at: datetime | None = None, hint: str = "openrouter management",
               cost: dict[str, int] | None = None) -> bytes:
    """Encrypt the management key into vault file contents (UTF-8 JSON). Nothing is written."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    check_management_key(management_key)
    check_passphrase(passphrase, management_key)
    if provider not in PROVIDERS:
        raise VaultError(f"unknown provider {provider!r}")
    if not isinstance(hint, str) or len(hint) > 100 or any(not c.isprintable() for c in hint):
        raise VaultError("the hint must be at most 100 printable characters")
    cost = {**DEFAULT_COST, **(cost or {})}
    _check_cost(cost["m_kib"], cost["t"], cost["p"])
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header: dict[str, Any] = {"v": VERSION, "kdf": KDF, "m_kib": cost["m_kib"], "t": cost["t"], "p": cost["p"],
                              "salt": _b64(salt), "nonce": _b64(nonce), "provider": provider,
                              "created": _iso(datetime.now(timezone.utc)),
                              "management_expires_at": _iso(management_expires_at), "hint": hint}
    key = _derive(passphrase, salt, cost["m_kib"], cost["t"], cost["p"])
    ct = AESGCM(key).encrypt(nonce, management_key.encode("utf-8"), _aad(header))
    header["ct"] = _b64(ct)
    return (json.dumps(header, indent=1, sort_keys=True) + "\n").encode("utf-8")


@dataclass(frozen=True)
class VaultHeader:
    """A parsed, validated vault, before decryption. Cheap: no Argon2 work yet."""
    raw: dict[str, Any]
    salt: bytes
    nonce: bytes
    ct: bytes

    @property
    def provider(self) -> str:
        return self.raw["provider"]

    @property
    def management_expires_at(self) -> datetime | None:
        return _parse_iso(self.raw["management_expires_at"])


def parse(data: bytes) -> VaultHeader:
    if len(data) > MAX_FILE_BYTES:
        raise VaultError("the vault file is too large")
    try:
        header = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise VaultError("the vault file is not JSON") from None
    if not isinstance(header, dict):
        raise VaultError("the vault file is not a JSON object")
    if set(header) != FIELDS:
        missing, extra = sorted(FIELDS - set(header)), sorted(set(header) - FIELDS)
        raise VaultError(f"the vault file has the wrong fields (missing {missing}, unexpected {extra})")
    if header["v"] != VERSION or header["kdf"] != KDF:
        raise VaultError(f"unsupported vault version or KDF ({header['v']!r}, {header['kdf']!r})")
    if header["provider"] not in PROVIDERS:
        raise VaultError(f"unknown provider {header['provider']!r} in the vault")
    _check_cost(header["m_kib"], header["t"], header["p"])
    for name in ("created", "hint"):
        if not isinstance(header[name], str):
            raise VaultError(f"vault field {name!r} must be text")
    _parse_iso(header["management_expires_at"])
    salt, nonce, ct = _unb64(header["salt"], "salt"), _unb64(header["nonce"], "nonce"), _unb64(header["ct"], "ct")
    if len(salt) != 16 or len(nonce) != 12:
        raise VaultError("the vault salt must be 16 bytes and the nonce 12 bytes")
    if not 17 <= len(ct) <= MAX_SECRET_BYTES + 16:
        raise VaultError("the vault ciphertext has an impossible length")
    return VaultHeader(raw=header, salt=salt, nonce=nonce, ct=ct)


def unseal_header(vault: VaultHeader, passphrase: str) -> Unsealed:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = vault.raw
    key = _derive(passphrase if isinstance(passphrase, str) else "", vault.salt, raw["m_kib"], raw["t"], raw["p"])
    try:
        plain = bytearray(AESGCM(key).decrypt(vault.nonce, vault.ct, _aad(raw)))
    except InvalidTag:
        raise WrongPassphrase("wrong passphrase, or the vault file was modified") from None
    try:
        plain.decode("utf-8")
    except UnicodeDecodeError:
        raise VaultError("the vault holds no text key") from None
    unsealed = Unsealed(plain, provider=raw["provider"], management_expires_at=vault.management_expires_at, hint=raw["hint"])
    for i in range(len(plain)):
        plain[i] = 0
    return unsealed


def unseal_bytes(data: bytes, passphrase: str) -> Unsealed:
    return unseal_header(parse(data), passphrase)


# ---------------------------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------------------------

def restrict(path: Path, *, directory: bool = False) -> str | None:
    """Owner-only access: an ACL with inheritance removed on Windows, 0600/0700 on POSIX. Best effort: returns a
    warning instead of raising, because the encryption is the protection."""
    try:
        if os.name == "nt":
            user = getpass.getuser()
            domain = os.environ.get("USERDOMAIN")
            principal = f"{domain}\\{user}" if domain else user
            icacls = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"
            grant = f"{principal}:(OI)(CI)F" if directory else f"{principal}:F"
            result = subprocess.run([str(icacls), str(path), "/inheritance:r", "/grant:r", grant],
                                    capture_output=True, timeout=30)
            if result.returncode != 0:
                return f"could not restrict {path} to the current user (icacls exit {result.returncode})"
        else:
            os.chmod(path, 0o700 if directory else 0o600)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"could not restrict {path} to the current user ({type(exc).__name__})"
    return None


def write_atomic(path: Path, data: bytes) -> list[str]:
    """Write to a restricted temp file in the same folder, fsync, then os.replace. Returns warnings."""
    warnings: list[str] = []
    path = Path(path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
        if (w := restrict(path.parent, directory=True)):
            warnings.append(w)
    fd, tmp = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=path.parent)
    try:
        if (w := restrict(Path(tmp))):
            warnings.append(w)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return warnings


def read_vault(path: Path) -> VaultHeader:
    path = Path(path)
    if not path.is_file():
        raise VaultError(f"no vault at {path}; create one with: python -m masqai.vault seal --path \"{path}\"")
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    return parse(data)


def seal_file(path: Path, management_key: str, passphrase: str, *, overwrite: bool = False, **kwargs: Any) -> list[str]:
    path = Path(path)
    if path.exists() and not overwrite:
        raise VaultError(f"{path} already exists; use repass to change the passphrase, or destroy it first")
    return write_atomic(path, seal_bytes(management_key, passphrase, **kwargs))


def destroy_file(path: Path) -> None:
    """Overwrite with random bytes, fsync, delete. (SSDs and journaling may keep old blocks: the file is encrypted
    anyway; the real fix for a lost passphrase is deleting the management key on OpenRouter.)"""
    path = Path(path)
    if not path.is_file():
        raise VaultError(f"no vault at {path}")
    size = path.stat().st_size
    with open(path, "r+b") as handle:
        handle.write(secrets.token_bytes(max(size, 1)))
        handle.flush()
        os.fsync(handle.fileno())
    path.unlink()


def unlock(path: Path, prompt: Callable[[str], str], *, attempts: int = 3) -> Unsealed:
    """Read and check the vault once, then ask for the passphrase up to `attempts` times (§3.1). Each wrong try costs
    one Argon2 derivation (about a second at the default cost)."""
    vault = read_vault(path)
    for attempt in range(attempts):
        passphrase = prompt(f"Passphrase for {path}: ")
        try:
            return unseal_header(vault, passphrase)
        except WrongPassphrase:
            left = attempts - attempt - 1
            if left:
                print(f"  wrong passphrase ({left} attempt{'s' if left > 1 else ''} left)", file=sys.stderr)
    raise VaultError(f"{attempts} wrong passphrase attempts for {path}")


def tty_prompt(prompt: str) -> str:
    """getpass, but only on a real terminal: without one getpass may echo the passphrase, so we refuse (§3.1)."""
    if not (sys.stdin and sys.stdin.isatty()):
        raise VaultError("a secret must be typed, but there is no interactive terminal; refusing "
                         "(there is deliberately no passphrase environment variable)")
    return getpass.getpass(prompt)


# ---------------------------------------------------------------------------------------------------------------
# CLI: python -m masqai.vault ...
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class Console:
    secret: Callable[[str], str] = tty_prompt
    ask: Callable[[str], str] = input
    say: Callable[[str], None] = print


async def _whoami(key: str, transport: Any = None) -> dict[str, Any]:
    from .openrouter import OpenRouterKeys
    client = OpenRouterKeys(key, transport=transport)
    try:
        return await client.current()
    finally:
        await client.aclose()


def check_with_openrouter(key: str, *, transport: Any = None) -> datetime | None:
    """The key must be a management key (GET /api/v1/key -> is_management_key). Returns its expiry if reported."""
    from .openrouter import parse_time
    try:
        current = asyncio.run(_whoami(key, transport))
    except ManagementAuthError:
        raise VaultError("OpenRouter refused this key (revoked, expired, or mistyped)") from None
    if current.get("is_management_key") is not True:
        raise VaultError("this is not a management key; create one under OpenRouter's Management API Keys")
    return parse_time(current.get("expires_at"))


def _ask_expiry(console: Console) -> datetime | None:
    text = console.ask("Management key expiry date (YYYY-MM-DD, empty if unknown): ").strip()
    if not text:
        console.say("  no expiry recorded: the gateway cannot warn before the management key expires")
        return None
    try:
        day = datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise VaultError("expected a date like 2027-01-31") from None
    return day.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)


def _new_passphrase(console: Console, key: str) -> str:
    first = console.secret(f"New passphrase (at least {MIN_PASSPHRASE} characters): ")
    check_passphrase(first, key)
    if console.secret("Repeat the passphrase: ") != first:
        raise VaultError("the passphrases do not match")
    return first


def cmd_seal(path: Path, console: Console, *, transport: Any = None, cost: dict[str, int] | None = None) -> None:
    if path.exists():
        raise VaultError(f"{path} already exists; use repass to change the passphrase, or destroy it first")
    key = console.secret("OpenRouter management key (input hidden): ").strip()
    check_management_key(key)
    console.say("  checking the key with OpenRouter...")
    expires = check_with_openrouter(key, transport=transport)
    if expires is None:
        expires = _ask_expiry(console)
    else:
        console.say(f"  OpenRouter reports the management key expires {_iso(expires)}")
    passphrase = _new_passphrase(console, key)
    for warning in seal_file(path, key, passphrase, management_expires_at=expires, cost=cost):
        console.say(f"  warning: {warning}")
    console.say(f"  sealed: {path}")
    console.say("  If you forget the passphrase: delete the management key on OpenRouter, create a new one and seal again.")


def cmd_verify(path: Path, console: Console, *, transport: Any = None) -> None:
    unsealed = unlock(path, console.secret)
    try:
        reported = check_with_openrouter(unsealed.reveal(), transport=transport)
    finally:
        stated = unsealed.management_expires_at
        unsealed.wipe()
    expires = reported or stated
    console.say("  ok: the vault opens and OpenRouter accepts the management key")
    if expires is not None:
        days = (expires - datetime.now(timezone.utc)).total_seconds() / 86400
        console.say(f"  management key expires {_iso(expires)} ({days:.0f} days)")


def cmd_repass(path: Path, console: Console, *, cost: dict[str, int] | None = None) -> None:
    vault = read_vault(path)
    unsealed = unlock(path, console.secret)
    try:
        key = unsealed.reveal()
        passphrase = _new_passphrase(console, key)
        warnings = seal_file(path, key, passphrase, overwrite=True, provider=unsealed.provider,
                             management_expires_at=unsealed.management_expires_at, hint=vault.raw["hint"], cost=cost)
    finally:
        unsealed.wipe()
    for warning in warnings:
        console.say(f"  warning: {warning}")
    console.say(f"  passphrase changed: {path}")


def cmd_destroy(path: Path, console: Console) -> None:
    read_vault(path)   # refuse to shred something that is not a vault
    if console.ask(f"Type 'destroy' to overwrite and delete {path}: ").strip() != "destroy":
        raise VaultError("not confirmed; nothing was changed")
    destroy_file(path)
    console.say(f"  destroyed: {path}. Delete the management key on OpenRouter too if it is no longer needed.")


def main(argv: list[str] | None = None, console: Console | None = None, *, transport: Any = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m masqai.vault", description="Key Enigma passphrase vault")
    parser.add_argument("command", choices=["seal", "verify", "repass", "destroy"])
    parser.add_argument("--path", default=None, help=f"vault file (default {default_path()})")
    parser.add_argument("--provider", default="openrouter", choices=list(PROVIDERS))
    args = parser.parse_args(argv)
    path = Path(args.path).expanduser() if args.path else default_path()
    console = console or Console()
    try:
        if args.command == "seal":
            cmd_seal(path, console, transport=transport)
        elif args.command == "verify":
            cmd_verify(path, console, transport=transport)
        elif args.command == "repass":
            cmd_repass(path, console)
        else:
            cmd_destroy(path, console)
    except CustodyError as exc:
        console.say(f"masqai.vault: {exc}")
        return 1
    except (KeyboardInterrupt, EOFError):
        console.say("masqai.vault: cancelled")
        return 130
    return 0
