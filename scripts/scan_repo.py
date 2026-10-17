"""Run MasqAI's own detectors over every tracked file: no real-looking secret may be committed.

    python scripts/scan_repo.py        # exit 1 and list findings if anything looks real

Synthetic values must say so: anything containing FAKE (any case), an obvious example sequence
(1234567890), a template ({{X}} or an f-string {…}) or a placeholder is allowed, and matches shorter
than 8 characters are prose ("password=" in a comment), not secrets. Emails and generic key=value hits are skipped (docs are full of examples);
key, token, credential and private-key rules are enforced. Findings print the file, line and rule,
never the matched value.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from masqai.detectors import load_rules  # noqa: E402

SKIP_RULES = {"email", "generic_key_value"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".db", ".lock"}
SKIP_FILES = {"web/package-lock.json"}


def synthetic(value: str) -> bool:
    lower = value.lower()
    return (len(value) < 8 or "fake" in lower or "1234567890" in value or "{" in value or value.startswith("<")
            or set(value[-8:]) <= {"x", "X", ".", "…"})


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout.split()
    rules = [r for r in load_rules() if r.name not in SKIP_RULES]
    findings = []
    for name in files:
        path = root / name
        if name in SKIP_FILES or path.suffix in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for rule in rules:
            for start, end in rule.hits(text):
                value = text[start:end]
                if value and not synthetic(value):
                    line = text.count("\n", 0, start) + 1
                    findings.append(f"{name}:{line}: {rule.name} ({len(value)} chars)")
    for finding in findings:
        print(finding)
    print(f"scan_repo: {len(files)} files, {len(findings)} real-looking secret(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
