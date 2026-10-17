# Plan

## Milestones

| # | Milestone | Done when | State |
|---|---|---|---|
| 1 | Core library, no network: `model.py`, `ops.py` (mask, hide, replace, relink, unmask; auto masks at word boundaries), `detectors.py` + `rules/*.toml` | `tests/test_core.py`, `tests/test_ops.py` pass | done |
| 2 | Proxy: endpoints, strict extraction, sessions/prefix/rollback, restore incl. streaming, fail closed, security-model client with one retry | `tests/test_proxy.py` passes | done |
| 3 | Hardening: section 7 + hygiene and pseudonyms | `tests/test_hardening.py` passes | done |
| 4 | GUI (four tabs) + replay export + `forwarded` events | GUI checked in a browser; export test passes | done |
| 5 | Freeze: injection set + report, `DECISIONS.md`, README sections | `tests/test_injection.py`; docs written | done |
| — | Eval harness on Daytona (`eval/`) | self-test smoke passes; `tests/test_eval.py` passes | done; real N=10/N=20 runs pending (needs `DAYTONA_API_KEY`, an upstream key, `qwen2.5:7b`) |
| — | Public site (`web/`) | `npm run build`, Lighthouse a11y 100 on `/` and `/demo` | done; real `results.json` pending the eval |
| stretch | Key Enigma, honeytoken canary (separate module behind a flag) | — | not started (only after milestone 5 is green and the owner agrees) |

## Layout

```
masqai/
  app.py          FastAPI app: middleware (Host, origin, token, CSP), control API, the proxy
  adapter.py      strict per-API extraction and write-back
  detectors.py    rule tables + host identifiers + custom values (masks only)
  rules/*.toml    detector rules as data
  ops.py          occurrence-bound operations, auto masks, rendering, validation (Applier)
  sanitize.py     detectors → auto masks → security model (one correction round) → render
  prompts/security.md   the default security-model prompt
  session.py      session matching, rollback, retention, forget
  hygiene.py      pseudonyms, stripped-header records
  restore.py      tool-call restore (non-streamed) and the streaming ArgumentStream
  streaming.py    SSE transformer for the three APIs
  replay.py       per-request records and the public site's replay export
  model.py, trace.py, observer.py, upstream.py, logs.py, config.py
  static/         the GUI (vanilla JS): ui, app, context, security, mapping, config
run_gateway.py    CLI: --config, --playground; prints the token URL
tests/            unit + end-to-end tests; tests/injection/ (fixtures + runner)
eval/             the Daytona harness (see eval/README.md)
playground/       six agent workspaces + the untrusted relay
web/              the public site (Next.js, static)
scripts/scan_repo.py   detectors over the repo (CI)
```
