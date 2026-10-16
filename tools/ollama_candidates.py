"""Find security-model candidates in the Ollama library (sorted by newest).

Usage:  python tools/ollama_candidates.py [--ram 32] [--days 365] [--top 25] [--details] [--html FILE]

Fetches https://ollama.com/library?sort=newest, parses every model (name, description,
capabilities, sizes, pulls, updated date), drops models that cannot do the job (embedding-only,
OCR, vision-only, code-only, guard classifiers), and scores the rest for a CPU-only machine:

  - fits in RAM at ~4-bit quantization (about 0.6 GB per billion parameters, plus headroom)
  - MoE models with few active parameters run much faster on CPU than dense models
  - "tools" capability is a proxy for reliable structured (JSON) output
  - newer and more pulled is better; "thinking"-only models cost latency

--details also fetches each top model's page to read architecture hints (MoE, active
parameters, context length) from its description. The heuristics are rough: they shortlist
models to test on the Security page, they do not replace that test.
"""
from __future__ import annotations

import argparse
import html
import math
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

URL = "https://ollama.com/library?sort=newest"
GB_PER_B = 0.6           # ~Q4_K_M weights per billion parameters
HEADROOM_GB = 6          # OS, browser, IDE, KV cache for a ~32k context

# Name/description hints for models that do not suit a general text-in, JSON-out inspector.
EXCLUDE = re.compile(r"embed|ocr|guard|shield|reranker|vision-only|\bvl\b|-vl\b|llava|moondream|"
                     r"coder|codellama|starcoder|codestral|deepseek-coder|sqlcoder|math|"
                     r"whisper|tts|audio-only|image|diffusion|clip", re.I)
MOE_HINT = re.compile(r"mixture[- ]of[- ]experts|\bMoE\b|(\d+(?:\.\d+)?)\s*[bB]\s*(?:total)?[^.]{0,40}?(\d+(?:\.\d+)?)\s*[bB]\s*active|"
                      r"-a(\d+(?:\.\d+)?)b\b|\ba(\d+(?:\.\d+)?)b\b", re.I)


@dataclass
class Model:
    name: str
    description: str
    capabilities: list[str] = field(default_factory=list)
    sizes: list[str] = field(default_factory=list)
    pulls: float = 0
    updated: datetime | None = None
    active_b: float | None = None     # active parameters for MoE, if detectable
    moe: bool = False
    context: str | None = None
    score: float = 0
    pick: str | None = None           # size tag chosen for this machine
    notes: list[str] = field(default_factory=list)


def parse_count(text: str) -> float:
    text = text.strip().upper().replace(",", "")
    mult = {"K": 1e3, "M": 1e6, "B": 1e9}.get(text[-1:], 1)
    try:
        return float(text.rstrip("KMB")) * mult
    except ValueError:
        return 0


def size_b(tag: str) -> float | None:
    """Parameter count in billions from a size tag: 8b, 270m, e4b, 30b-a3b, 8x7b."""
    tag = tag.lower()
    if m := re.fullmatch(r"(\d+)x(\d+(?:\.\d+)?)b", tag):
        return float(m.group(1)) * float(m.group(2))
    if m := re.fullmatch(r"e?(\d+(?:\.\d+)?)([bm])(?:-a\d+(?:\.\d+)?b)?", tag):
        value = float(m.group(1))
        return value / 1000 if m.group(2) == "m" else value
    return None


def fetch(url: str) -> str:
    response = httpx.get(url, timeout=30, follow_redirects=True, headers={"user-agent": "masqai-model-finder/1"})
    response.raise_for_status()
    return response.text


def parse_library(page: str) -> list[Model]:
    models = []
    for block in re.findall(r'<li[^>]*>\s*<a href="/library/[^"]+".*?</li>', page, re.S):
        name = re.search(r'href="/library/([^"]+)"', block).group(1)
        desc = re.search(r"<p class=\"max-w-lg[^\"]*\">(.*?)</p>", block, re.S)
        badges = [html.unescape(b.strip()) for b in re.findall(r"<span\s+class=\"inline-flex[^\"]*\">([^<]+)</span>", block)]
        sizes = [b for b in badges if size_b(b) is not None]
        caps = [b for b in badges if b not in sizes]
        pulls = re.search(r"<span\s*>([\d.,]+[KMB]?)</span>\s*<span[^>]*>&nbsp;Pulls", block)
        updated = re.search(r'title="([A-Z][a-z]{2} \d{1,2}, \d{4}[^"]*UTC)"', block)
        model = Model(name, html.unescape(re.sub(r"\s+", " ", desc.group(1)).strip()) if desc else "", caps, sizes,
                      parse_count(pulls.group(1)) if pulls else 0)
        if updated:
            try:
                model.updated = datetime.strptime(updated.group(1), "%b %d, %Y %I:%M %p UTC").replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        models.append(model)
    return models


def detect_moe(model: Model, text: str) -> None:
    """Record active parameters per total size, e.g. "30B ... 3B active", "24B-A2B", "30b-a3b".
    A family-level "MoE" mention alone is not applied to every size (families mix dense and MoE)."""
    pairs: dict[float, float] = getattr(model, "_moe_pairs", {})
    for tag in model.sizes:
        if m := re.fullmatch(r"(\d+(?:\.\d+)?)b-a(\d+(?:\.\d+)?)b", tag.lower()):
            pairs[float(m.group(1))] = float(m.group(2))
    patterns = [
        r"(\d+(?:\.\d+)?)\s*B[- ]A(\d+(?:\.\d+)?)\s*B\b",                                     # 24B-A2B
        r"(\d+(?:\.\d+)?)\s*B\b[^.\n]{0,60}?\bwith\s+(\d+(?:\.\d+)?)\s*B\s+activ",               # 30B MoE with 3B active
        r"(\d+(?:\.\d+)?)\s*B\s+(?:total\s+)?param\w*[^.\n]{0,40}?(\d+(?:\.\d+)?)\s*B\s+activ",  # 21B parameters with 3.6B active
        r"(\d+(?:\.\d+)?)\s*[bB]\s*total[^.\n]{0,20}?(\d+(?:\.\d+)?)\s*[bB]\s*activ",
    ]
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.I):
            total, active = float(m.group(1)), float(m.group(2))
            if active < total:
                pairs.setdefault(total, active)
    model._moe_pairs = pairs
    if c := re.search(r"(\d+)\s*[kK]\s*(?:token)?s?\s*context|context (?:window|length) of (?:up to )?(\d+)\s*[kK]", text):
        model.context = (c.group(1) or c.group(2)) + "K"


def active_for(model: Model, params: float) -> float | None:
    """Active parameters of the size `params`, if known to be MoE (match totals within 15%)."""
    for total, active in getattr(model, "_moe_pairs", {}).items():
        if abs(total - params) <= 0.15 * total:
            return active
    return None


def score_size(model: Model, params: float, active: float | None, now: datetime) -> float:
    run = active if active else params
    quality = min(math.log2(max(params, 0.5)) / math.log2(32), 1.0)
    if params < 3:
        quality *= 0.3
    speed = min(4 / max(run, 1), 1.0)
    s = 0.55 * quality + 0.30 * speed
    if "tools" in model.capabilities:
        s += 0.10
    if model.updated:
        s += 0.10 * max(0, 1 - (now - model.updated).days / 365)
    s += 0.05 * min(math.log10(max(model.pulls, 1)) / 7, 1)
    return s


def score(model: Model, ram_gb: float, now: datetime) -> None:
    budget = ram_gb - HEADROOM_GB
    fitting = [(t, size_b(t)) for t in model.sizes if (size_b(t) or 0) * GB_PER_B <= budget]
    if not fitting:
        model.score = -1
        model.notes = [f"no size fits {budget:.0f} GB at ~Q4"]
        return
    # Best-scoring size that fits: a fast MoE size can beat a bigger dense one.
    best = max(fitting, key=lambda pair: score_size(model, pair[1], active_for(model, pair[1]), now))
    model.pick, params = best
    active = active_for(model, params)
    model.moe, model.active_b = active is not None, active
    model.score = round(score_size(model, params, active, now), 3)
    model.notes = [f"~{params * GB_PER_B:.0f} GB" + (f", MoE {active:g}B active" if active else ", dense or unknown")]
    if params < 3:
        model.notes.append("small: expect missed values and bad copies")
    if "tools" not in model.capabilities:
        model.notes.append("no tools tag: JSON reliability unknown")
    if "thinking" in model.capabilities:
        model.notes.append("thinking: turn off or allow a long timeout")


def main() -> int:
    # The Windows console defaults to a legacy code page; model descriptions contain Unicode.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ram", type=float, default=32, help="system RAM in GB (CPU inference)")
    parser.add_argument("--days", type=int, default=730, help="ignore models not updated within this many days")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--details", action="store_true", help="fetch each top model's page for MoE/context hints")
    parser.add_argument("--html", help="parse a saved copy of the library page instead of fetching it")
    parser.add_argument("--all", action="store_true", help="also list excluded and non-fitting models")
    args = parser.parse_args()

    page = open(args.html, encoding="utf-8").read() if args.html else fetch(URL)
    models = parse_library(page)
    if not models:
        print("No models parsed: the page layout may have changed.", file=sys.stderr)
        return 1
    now = datetime.now(timezone.utc)
    kept, dropped = [], []
    for model in models:
        text_only = "embedding" in model.capabilities
        if text_only or EXCLUDE.search(model.name) or EXCLUDE.search(model.description.split(".")[0]):
            dropped.append((model, "not a general text model"))
            continue
        if model.updated and (now - model.updated).days > args.days:
            dropped.append((model, f"not updated in {args.days} days"))
            continue
        detect_moe(model, model.description)
        score(model, args.ram, now)
        kept.append(model) if model.score >= 0 else dropped.append((model, model.notes[-1]))

    kept.sort(key=lambda m: -m.score)
    # Detail pages are fetched for a wider pool, since MoE info there can change the ranking.
    top = kept[: max(args.top * 2, args.top)] if args.details else kept[: args.top]
    if args.details:
        import asyncio

        async def fetch_all(names: list[str]) -> dict[str, str | Exception]:
            limit = asyncio.Semaphore(8)
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"user-agent": "masqai-model-finder/1"}) as client:
                async def one(name: str):
                    async with limit:
                        try:
                            response = await client.get(f"https://ollama.com/library/{name}")
                            response.raise_for_status()
                            print(f"  fetched {name}", file=sys.stderr)
                            return name, response.text
                        except httpx.HTTPError as exc:
                            return name, exc
                return dict(await asyncio.gather(*(one(m.name) for m in top)))

        print(f"Fetching {len(top)} model pages…", file=sys.stderr)
        pages = asyncio.run(fetch_all([m.name for m in top]))
        for model in top:
            page_text = pages.get(model.name)
            if isinstance(page_text, str):
                detect_moe(model, html.unescape(re.sub(r"<[^>]+>", " ", page_text)))
                score(model, args.ram, now)
            else:
                model.notes.append(f"details failed: {page_text.__class__.__name__}")
        top.sort(key=lambda m: -m.score)
        top = top[: args.top]

    print(f"Parsed {len(models)} models from {URL}; {len(kept)} candidates for {args.ram:g} GB RAM (CPU).\n")
    print(f"{'#':>2}  {'score':>5}  {'pull this':<28} {'updated':<11} {'pulls':>7}  capabilities / notes")
    for i, m in enumerate(top, 1):
        tag = f"{m.name}:{m.pick}"
        date = m.updated.strftime("%Y-%m-%d") if m.updated else "?"
        pulls = f"{m.pulls / 1e6:.1f}M" if m.pulls >= 1e6 else f"{m.pulls / 1e3:.0f}K" if m.pulls >= 1e3 else f"{m.pulls:.0f}"
        caps = ",".join(c for c in m.capabilities if c != "cloud") or "-"
        print(f"{i:>2}  {m.score:>5.2f}  {tag:<28} {date:<11} {pulls:>7}  [{caps}] {'; '.join(m.notes)}"
              + (f"; ctx {m.context}" if m.context else ""))
        print(f"{'':>10}{m.description[:150]}")
    if args.all:
        print("\nExcluded:")
        for m, why in dropped:
            print(f"  {m.name:<30} {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
