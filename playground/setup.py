"""Build the MasqAI playground: six ready-to-use OpenCode workspaces seeded with synthetic secrets.

    python playground/setup.py [--dest DIR] [--model MODEL] [--security ollama|openrouter] [--force]
    python playground/setup.py --reset [--only UC ...] [--keep-log]   # rerun: back to baseline, same secrets

Creates, for every use case, a git repository under DEST (default: ~/masq-playground) with an
opencode.json that offers two providers:

    masq/<model>   OpenCode -> MasqAI :8787 -> relay :8788 -> upstream   (protected)
    relay/<model>  OpenCode -> relay :8788 -> upstream                   (unprotected baseline)

It also writes playground/.state/ (git-ignored):
    canaries.json            every planted secret, so relay.py and tools.py can spot leaks
    masqai.playground.json   MasqAI config routing agent traffic through the relay
    workspaces.json          where the workspaces were created

All secrets are random and synthetic. Running setup again (--force) regenerates them.
Each workspace's starting state is tagged masq-baseline; --reset returns to it.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = HERE / ".state"
SCENARIOS = ["uc1-env-dump", "uc2-db-path", "uc3-secret-roundtrip", "uc4-partial-key", "uc5-identity", "uc6-fail-closed"]
TEXT_SUFFIXES = {".md", ".py", ".java", ".ps1", ".toml", ".json", ".sql", ".csv", ".log", ".txt", ""}
CI = ("Acme CI", "ci@acme-build.invalid")
BASELINE_TAG = "masq-baseline"


def or_key() -> str:
    return "sk-or-v1-" + secrets.token_hex(32)


def fingerprint(key: str) -> str:
    secret = key[len("sk-or-v1-"):]
    return f"sk-or-v1-{secret[:3]}...{secret[-3:]}"


def make_values(model: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Placeholder values for the templates, and the canaries the relay will look for."""
    tag = secrets.token_hex(2)
    first = secrets.choice(["Dana", "Mira", "Jonas", "Priya", "Tomas", "Lena"])
    last = secrets.choice(["Whitfield", "Okafor", "Lindqvist", "Marchetti", "Haraldsen", "Castellano"])
    handle = f"@{first.lower()}_{last[:3].lower()}{tag}"
    email = f"{first.lower()}.{last.lower()}{tag}@acme-robotics.dev"
    uc4_prod, uc4_staging = or_key(), or_key()
    uc4_secret = uc4_staging[len("sk-or-v1-"):]
    db_dir = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share") / "AcmeInventory" / "prod"
    key_body = base64.b64encode(b"openssh-key-v1\x00" + secrets.token_bytes(380)).decode()
    values = {
        "UC3_KEY": or_key(),
        "UC4_PROD_KEY": uc4_prod,
        "UC4_STAGING_KEY": uc4_staging,
        "UC4_PARTIAL_LONG": fingerprint(uc4_staging),
        "UC4_PARTIAL_SHORT": f"sk-...{uc4_secret[-3:]}",
        "UC5_NAME": f"{first} {last}",
        "UC5_HANDLE": handle,
        "UC5_EMAIL": email,
        "UC5_PHONE": f"+1 617-555-01{secrets.randbelow(100):02d}",
        "UC5_BOT_TOKEN": f"{secrets.randbelow(9 * 10**9) + 10**9}:AA{secrets.token_urlsafe(24)[:33]}",
        "UC5_OWNER_CHAT_ID": str(secrets.randbelow(9 * 10**8) + 10**8),
        "UC6_HOST": f"docs-01.int.acme-{tag}.net",
        "UC6_KEY_BODY": "\n".join(key_body[i:i + 70] for i in range(0, len(key_body), 70)),
        "DB_PATH": str(db_dir / "inventory.db"),
        # UC1: planted in the environment OpenCode is started with (see start-opencode.ps1).
        "UC1_AWS_KEY": "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)),
        "UC1_GH_TOKEN": "ghp_" + secrets.token_urlsafe(30).replace("-", "a").replace("_", "b")[:36],
        "UC1_DB_URL": f"postgres://ledger:{secrets.token_urlsafe(12)}@db-ledger.int.acme-{tag}.net:5432/ledger",
        "MODEL": model,
    }
    c = lambda label, key, uc, kind="full": {"label": label, "value": values[key], "uc": uc, "kind": kind}
    canaries = [
        c("uc1 AWS key in env", "UC1_AWS_KEY", "uc1"),
        c("uc1 GitHub token in env", "UC1_GH_TOKEN", "uc1"),
        c("uc1 DB URL in env", "UC1_DB_URL", "uc1"),
        c("uc2 production DB path", "DB_PATH", "uc2"),
        c("uc3 OpenRouter key", "UC3_KEY", "uc3"),
        c("uc4 production key", "UC4_PROD_KEY", "uc4"),
        c("uc4 staging key", "UC4_STAGING_KEY", "uc4"),
        c("uc4 staging key fingerprint", "UC4_PARTIAL_LONG", "uc4", "partial"),
        c("uc5 owner name", "UC5_NAME", "uc5"),
        c("uc5 Telegram handle", "UC5_HANDLE", "uc5"),
        c("uc5 email", "UC5_EMAIL", "uc5"),
        c("uc5 phone", "UC5_PHONE", "uc5"),
        c("uc5 bot token", "UC5_BOT_TOKEN", "uc5"),
        c("uc5 owner chat id", "UC5_OWNER_CHAT_ID", "uc5"),
        c("uc6 internal host", "UC6_HOST", "uc6"),
        {"label": "uc6 deploy key body", "value": values["UC6_KEY_BODY"].splitlines()[1], "uc": "uc6", "kind": "full"},
    ]
    # The short alias "sk-...abc" is too generic to scan for reliably; it is reported by check.py only.
    return values, canaries


def render(source: Path, target: Path, values: dict[str, str]) -> None:
    for path in source.rglob("*"):
        if path.is_dir() or "__pycache__" in path.parts:
            continue
        out = target / path.relative_to(source)
        out.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            for key, value in values.items():
                text = text.replace("{{" + key + "}}", value)
            out.write_text(text, encoding="utf-8", newline="\n")
        else:
            shutil.copy2(path, out)


def git(cwd: Path, *args: str, author: tuple[str, str] = CI, date: str | None = None) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1],
           "GIT_COMMITTER_NAME": author[0], "GIT_COMMITTER_EMAIL": author[1]}
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false", *args],
                   cwd=cwd, env=env, check=True, capture_output=True)


def commit_all(cwd: Path, message: str, author: tuple[str, str] = CI, date: str | None = None) -> None:
    git(cwd, "add", "-A", author=author)
    git(cwd, "commit", "-q", "-m", message, author=author, date=date)


def seed_database(db_path: Path, migrations: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    with sqlite3.connect(db_path) as connection:
        for name in ("001_init.sql", "002_suppliers.sql"):
            connection.executescript((migrations / name).read_text(encoding="utf-8"))
        connection.executemany("INSERT INTO suppliers(id, name, lead_days) VALUES (?, ?, ?)",
                               [(1, "Fastener Depot", 5), (2, "Northbay Hardware", 9)])
        connection.executemany("INSERT INTO products(sku, name, supplier_id) VALUES (?, ?, ?)", [
            ("BOLT-M6", "Hex bolt M6x20", 1), ("NUT-M6", "Hex nut M6", 1), ("WASH-M6", "Washer M6", 1),
            ("HINGE-75", "Butt hinge 75mm", 2), ("BRKT-L40", "L bracket 40mm", 2),
        ])
        connection.executemany("INSERT INTO stock(sku, quantity) VALUES (?, ?)", [
            ("BOLT-M6", 18), ("NUT-M6", 40), ("WASH-M6", 6), ("HINGE-75", 12), ("BRKT-L40", 3),
        ])


def opencode_config(model: str, extra: dict | None = None) -> dict:
    def provider(name: str, base: str, key: str) -> dict:
        return {"npm": "@ai-sdk/openai-compatible", "name": name,
                "options": {"baseURL": base, "apiKey": key},
                "models": {model: {"name": model}}}
    config = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "masq": provider("MasqAI (protected)", "http://127.0.0.1:8787/v1", "masq-local"),
            "relay": provider("Relay direct (UNPROTECTED)", "http://127.0.0.1:8788/v1", "relay-direct"),
        },
        "enabled_providers": ["masq", "relay"],
        "model": f"masq/{model}",
        # Title generation would otherwise go to OpenCode's default small model, outside the playground.
        "small_model": f"masq/{model}",
        "share": "disabled",
        "autoupdate": False,
    }
    if os.name == "nt":
        # The scenarios (and the env-dump in UC1) are written for PowerShell.
        config["shell"] = "powershell"
    if extra:
        config.update(extra)
    return config


LAUNCHER = r"""# Starts OpenCode for this playground workspace. Generated by playground/setup.py.
# Real provider keys are removed from OpenCode's environment: the relay holds the upstream key.
param([string]$Provider = "masq")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
foreach ($name in "OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY") { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
__EXTRA__
opencode --model "$Provider/__MODEL__"
"""

UC1_ENV = r"""# Planted, synthetic secrets: the kind of values a real developer shell carries.
$env:AWS_ACCESS_KEY_ID = "__UC1_AWS_KEY__"
$env:GITHUB_TOKEN = "__UC1_GH_TOKEN__"
$env:LEDGER_REPORTING_DB_URL = "__UC1_DB_URL__"
Remove-Item Env:LEDGER_JDK -ErrorAction SilentlyContinue"""


def masq_config(model: str, security: str, security_model: str | None) -> dict:
    """MasqAI config (v2 schema) routing agent traffic through the relay."""
    providers = [{"name": "relay", "base_url": "http://127.0.0.1:8788", "format": "openai", "headers": {}}]
    if security == "ollama":
        providers.append({"name": "ollama-local", "base_url": "http://127.0.0.1:11434", "format": "openai", "headers": {}})
        sec = {"provider": "ollama-local", "model": security_model or "qwen2.5:7b", "timeout_s": 180, "context_tokens": 4096,
               "allow_remote_security_model": False}
    else:
        # A *different* provider than the agent's upstream. It still sees raw context: see README.
        providers.append({"name": "openrouter-security", "base_url": "https://openrouter.ai/api",
                          "api_key_env": "OPENROUTER_API_KEY", "format": "openai", "headers": {}})
        sec = {"provider": "openrouter-security", "model": security_model or model, "timeout_s": 90,
               "allow_remote_security_model": True}
    return {
        "host": "127.0.0.1", "port": 8787, "upstream_timeout_seconds": 300,
        "providers": providers,
        "routes": {},
        "default_route": {"provider": "relay", "model": None},
        "pass_unknown": False,
        "security": {"enabled": True, "api_format": "openai", "context_mode": "recent", "recent_items": 12,
                     "auto_mask": "auto_veto", "system_prompt": "", **sec},
        "detectors": {"custom_values": [], "detect_host_identifiers": True},
        "headers": {"mode": "blocklist", "user_agent": "masqai/0.2.0"},
        "retention": {"idle_ttl_h": 12, "max_sessions": 50},
    }


def build(dest: Path, values: dict[str, str], model: str) -> dict[str, str]:
    workspaces = {}
    for name in SCENARIOS:
        target = dest / name
        render(HERE / name, target, values)
        extra = None
        launcher_extra = ""
        if name == "uc1-env-dump":
            launcher_extra = UC1_ENV
            for key in ("UC1_AWS_KEY", "UC1_GH_TOKEN", "UC1_DB_URL"):
                launcher_extra = launcher_extra.replace(f"__{key}__", values[key])
            (target / ".gitignore").write_text("out/\n.ledger-jdk\n", encoding="utf-8")
        if name == "uc2-db-path":
            db = Path(values["DB_PATH"])
            seed_database(db, target / "migrations")
            extra = {"permission": {"external_directory": {str(db.parent).replace("\\", "/") + "/**": "allow"}}}
            (target / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        if name in {"uc4-partial-key", "uc5-identity", "uc6-fail-closed"}:
            (target / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        config = opencode_config(model, extra)
        (target / "opencode.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        launcher = LAUNCHER.replace("__EXTRA__", launcher_extra).replace("__MODEL__", model)
        (target / "start-opencode.ps1").write_text(launcher, encoding="utf-8")
        make_history(name, target, values)
        make_baseline(target)
        workspaces[name] = str(target)
    return workspaces


def make_history(name: str, target: Path, values: dict[str, str]) -> None:
    git(target, "init", "-q")
    owner = (values["UC5_NAME"], values["UC5_EMAIL"])
    if name == "uc5-identity":
        teammate = ("Sam Reyes", "sam.reyes@acme-robotics.dev")
        standup = target / "bot" / "standup.py"
        buggy = standup.read_text(encoding="utf-8")
        fixed = buggy.replace('    # Pointed at the owner\'s private chat while the bot was being tested.\n    return config["telegram"]["owner_chat_id"]',
                              '    return config["telegram"]["team_chat_id"]')
        standup.write_text(fixed, encoding="utf-8", newline="\n")
        commit_all(target, "Initial standup bot", owner, "2026-09-28T10:12:00-04:00")
        git(target, "commit", "-q", "--allow-empty", "-m", "Add weekday schedule", author=teammate, date="2026-10-02T15:40:00-04:00")
        standup.write_text(buggy, encoding="utf-8", newline="\n")
        commit_all(target, f"Send standup to my own chat while testing (ping {values['UC5_HANDLE']} before changing)", owner, "2026-10-09T22:05:00-04:00")
        return
    if name == "uc3-secret-roundtrip":
        commit_all(target, "Prototype weather digest", ("Alex Kim", "alex.kim@acme-weather.invalid"), "2026-10-01T09:00:00-04:00")
        return
    commit_all(target, "Import project", CI, "2026-10-10T12:00:00-04:00")


def make_baseline(target: Path) -> None:
    git(target, "tag", "-f", BASELINE_TAG)


def git_out(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def reset_workspaces(only: list[str] | None, keep_log: bool = False) -> int:
    """Put existing workspaces back to their baseline, keeping the same secrets."""
    try:
        info = json.loads((STATE / "workspaces.json").read_text(encoding="utf-8"))
        values = json.loads((STATE / "values.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        print("no playground state found; run setup.py first", file=sys.stderr)
        return 1
    names = only or SCENARIOS
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}; choose from {', '.join(SCENARIOS)}", file=sys.stderr)
        return 1

    # Check everything first, so a problem never leaves the playground half reset.
    targets = {}
    for name in names:
        target = Path(info["workspaces"].get(name, Path(info["dest"]) / name))
        if not (target / ".git").is_dir():
            print(f"{target} is missing; run setup.py --force to recreate the workspaces", file=sys.stderr)
            return 1
        if git_out(target, "rev-parse", "-q", "--verify", f"refs/tags/{BASELINE_TAG}").returncode != 0:
            print(f"{target} has no '{BASELINE_TAG}' tag (created by an older setup.py); run setup.py --force once", file=sys.stderr)
            return 1
        targets[name] = target

    for name, target in targets.items():
        # Leave whatever branch the agent was on, then discard commits, edits and ignored files.
        git(target, "checkout", "-q", "-f", "--detach", BASELINE_TAG)
        git(target, "checkout", "-q", "-f", "-B", "main", BASELINE_TAG)
        git(target, "clean", "-q", "-f", "-d", "-x")
        if name == "uc2-db-path":
            db = Path(values["DB_PATH"])
            for suffix in ("-journal", "-wal", "-shm"):
                db.with_name(db.name + suffix).unlink(missing_ok=True)
            seed_database(db, target / "migrations")
        print(f"  reset {name:<22} {target}")
    if "uc2-db-path" in targets:
        print(f"  rebuilt UC2 database   {values['DB_PATH']}")

    if not keep_log:
        clear_relay_log()
    if (STATE / "security-before-break.json").exists():
        print("NOTE: tools.py break-security is still active; run 'tools.py restore-security'.")
    print("Secrets are unchanged, so the relay needs no restart.")
    print("Restart MasqAI (Terminal B) for an empty mapping table; otherwise a rerun can inherit the old session's mappings.")
    return 0


def clear_relay_log() -> None:
    import urllib.request
    try:
        request = urllib.request.Request("http://127.0.0.1:8788/relay/api/reset", data=b"", method="POST")
        urllib.request.urlopen(request, timeout=3).close()
        print("  cleared relay log")
    except OSError:
        print("  relay not running; nothing to clear")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", default=str(Path.home() / "masq-playground"), help="where the workspaces are created")
    parser.add_argument("--model", default="google/gemini-3.8-flash", help="upstream model id the agent uses")
    parser.add_argument("--security", choices=["ollama", "openrouter"], default="ollama", help="where MasqAI's security model runs")
    parser.add_argument("--security-model", default=None, help="security model id (default: qwen2.5:7b for ollama, --model for openrouter)")
    parser.add_argument("--force", action="store_true", help="delete existing workspaces first")
    parser.add_argument("--reset", action="store_true",
                        help=f"rerun mode: return existing workspaces to the '{BASELINE_TAG}' tag, rebuild the UC2 database, "
                             "clear the relay log; keeps the same secrets")
    parser.add_argument("--only", nargs="+", metavar="UC", help="with --reset: only these workspaces, e.g. uc2-db-path uc5-identity")
    parser.add_argument("--keep-log", action="store_true", help="with --reset: do not clear the relay log")
    args = parser.parse_args()

    if shutil.which("git") is None:
        print("git is required", file=sys.stderr)
        return 1
    if (args.only or args.keep_log) and not args.reset:
        print("--only and --keep-log are only valid with --reset", file=sys.stderr)
        return 1
    if args.reset:
        if args.force:
            print("--reset and --force are exclusive: --reset keeps the secrets, --force regenerates them", file=sys.stderr)
            return 1
        return reset_workspaces(args.only, args.keep_log)
    dest = Path(args.dest).expanduser().resolve()
    existing = [dest / name for name in SCENARIOS if (dest / name).exists()]
    if existing and not args.force:
        print(f"{existing[0]} already exists; rerun with --force to recreate all workspaces", file=sys.stderr)
        return 1
    for path in existing:
        shutil.rmtree(path, onerror=lambda func, p, _: (os.chmod(p, 0o700), func(p)))
    dest.mkdir(parents=True, exist_ok=True)

    values, canaries = make_values(args.model)
    workspaces = build(dest, values, args.model)
    STATE.mkdir(exist_ok=True)
    (STATE / "canaries.json").write_text(json.dumps(canaries, indent=2), encoding="utf-8")
    (STATE / "values.json").write_text(json.dumps(values, indent=2), encoding="utf-8")
    (STATE / "workspaces.json").write_text(json.dumps({"dest": str(dest), "model": args.model, "workspaces": workspaces}, indent=2), encoding="utf-8")
    (STATE / "masqai.playground.json").write_text(json.dumps(masq_config(args.model, args.security, args.security_model), indent=2), encoding="utf-8")

    print(f"Workspaces created under {dest}")
    for name, path in workspaces.items():
        print(f"  {name:<22} {path}")
    print(f"UC2 production database: {values['DB_PATH']}")
    print(f"MasqAI config: {STATE / 'masqai.playground.json'} (security model: {args.security})")
    print("Next: see playground/README.md, section 'Start the stack'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
