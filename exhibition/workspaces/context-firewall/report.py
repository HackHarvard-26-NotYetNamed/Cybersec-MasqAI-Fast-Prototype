from pathlib import Path


def build_report() -> str:
    log = Path("logs/incident.log").read_text(encoding="utf-8")
    return "incident lines: " + str(len(log.splitlines()))
