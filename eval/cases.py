"""Use cases (eval/cases/<id>/) and per-run canaries.

Each case folder holds:
  case.toml   title, workdir, canaries, env
  task.md     the user prompt given to the agent
  seed.sh     plants the run's canaries (runs once in the sandbox, from outside the workspace)
  check.sh    exit code 0 = the task succeeded (runs in the sandbox after the agent finishes)
  workspace/  files uploaded into the workdir

Every text file is a template: {{CANARY_<NAME>}} becomes that run's canary value, {{ROOT}} the
sandbox's root for this run. Canaries are generated fresh per run with secrets.token_hex, so one
run's leak can never be confused with another's. They live in RAM only and never reach eval/out/.
"""
from __future__ import annotations

import re
import secrets
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CASES_DIR = Path(__file__).parent / "cases"
FIRST = ["Dana", "Mira", "Jonas", "Priya", "Tomas", "Lena", "Omar", "Ines", "Kenji", "Ruth"]
LAST = ["Whitfield", "Okafor", "Lindqvist", "Marchetti", "Haraldsen", "Castellano", "Ivanova", "Moreau", "Tanaka", "Byrne"]
STREETS = ["Elm", "Summer", "Highland", "Cedar", "Willow", "Prospect", "Linden", "Beacon"]
KEY_KINDS = {"key"}


@dataclass
class Canary:
    name: str        # template name: {{CANARY_<name>}}
    kind: str        # generator; "key" canaries also leak through any 12+ char piece of their random part
    value: str
    secret_part: str = ""   # the random part of a key (substring rule)
    scan: bool = True


@dataclass
class Case:
    id: str
    title: str
    path: Path
    workdir: str
    canary_specs: list[dict]
    env: dict[str, str] = field(default_factory=dict)
    expected_block_status: int | None = None

    def task(self) -> str:
        return (self.path / "task.md").read_text(encoding="utf-8").strip()


def load_cases(selection: str = "all") -> list[Case]:
    ids = sorted(p.name for p in CASES_DIR.iterdir() if (p / "case.toml").is_file())
    if selection != "all":
        wanted = [s.strip() for s in selection.split(",") if s.strip()]
        missing = [w for w in wanted if w not in ids]
        if missing:
            raise SystemExit(f"unknown case(s): {', '.join(missing)}; available: {', '.join(ids)}")
        ids = wanted
    cases = []
    for case_id in ids:
        path = CASES_DIR / case_id
        meta = tomllib.loads((path / "case.toml").read_text(encoding="utf-8"))
        expected = meta.get("expected_block_status")
        if expected is not None and expected not in {400, 404, 422, 502, 503}:
            raise ValueError(f"{case_id}: unsupported expected_block_status {expected!r}")
        cases.append(Case(case_id, meta["title"], path, meta.get("workdir", "{{ROOT}}/ws"),
                          meta.get("canary", []), meta.get("env", {}), expected))
    return cases


def generate(kind: str, values: dict[str, str], spec: dict) -> Canary:
    hex6 = secrets.token_hex(3)
    name = spec["name"]
    if kind == "user":
        return Canary(name, kind, f"alice_{hex6}")
    if kind == "slug":
        # A unique-per-run path component; part of a scanned canary, not scanned on its own.
        return Canary(name, kind, f"acme-{hex6}", scan=spec.get("scan", False))
    if kind == "host":
        return Canary(name, kind, f"build-{hex6}.int.acme-{secrets.token_hex(2)}.net")
    if kind == "key":
        rand = secrets.token_hex(32)
        prefix = spec.get("prefix", "sk-or-v1-")
        return Canary(name, kind, f"{prefix}FAKE{rand}", secret_part=rand)
    if kind == "fingerprint":
        # A partial form of another key canary: prefix + first 3 + "..." + last 3 of its random part.
        source = values[spec["of"]]
        rand = source.split("FAKE", 1)[1]
        return Canary(name, kind, f"sk-or-v1-{rand[:3]}...{rand[-3:]}")
    if kind == "name":
        return Canary(name, kind, f"{secrets.choice(FIRST)} {secrets.choice(LAST)}-{secrets.choice(LAST)}")
    if kind == "email":
        return Canary(name, kind, f"{secrets.choice(FIRST).lower()}.{hex6}@acme-{secrets.token_hex(2)}.dev")
    if kind == "handle":
        return Canary(name, kind, f"@{secrets.choice(FIRST).lower()}_{hex6}")
    if kind == "address":
        return Canary(name, kind, f"{secrets.randbelow(900) + 100} {secrets.choice(STREETS)} St, Apt {secrets.randbelow(40) + 1}, Somerville, MA")
    if kind == "derived":
        return Canary(name, kind, render(spec["template"], values, ""), scan=spec.get("scan", True))
    raise ValueError(f"unknown canary kind {kind!r}")


def make_canaries(case: Case, root: str) -> list[Canary]:
    canaries: list[Canary] = []
    values: dict[str, str] = {"ROOT": root}
    for spec in case.canary_specs:
        canary = generate(spec["kind"], values, spec)
        canaries.append(canary)
        values[canary.name] = canary.value
    return canaries


def render(text: str, values: dict[str, str], root: str) -> str:
    """{{CANARY_X}} -> value, {{ROOT}} -> root. Fails loudly on an unknown template name."""
    def sub(match: re.Match[str]) -> str:
        key = match.group(1)
        if key == "ROOT":
            return root or values.get("ROOT", "")
        if key.startswith("CANARY_") and key[7:] in values:
            return values[key[7:]]
        raise KeyError(f"unknown template {{{{{key}}}}}")
    return re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, text)


def files(case: Case) -> list[tuple[str, bytes]]:
    """Workspace files as (relative path, template bytes)."""
    base = case.path / "workspace"
    return [(p.relative_to(base).as_posix(), p.read_bytes()) for p in sorted(base.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts] if base.is_dir() else []
