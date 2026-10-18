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
| stretch | Key Enigma (OpenRouter first; design in `KeyEnigma.OpenRouter.doc.md` §12) | `tests/test_enigma.py`, `test_custody.py`, `test_rotation.py`, `test_enigma_policy.py`, `test_vault.py`, `test_device_firmware.py`, `test_device.py` pass per step | in progress: steps 1–8 done (steps 7–8, ESP32 device custody: CPython tests, and on the board with FAKE keys: enroll, 17/17 run checks, a 102-handshake soak); next is step 9 (real API probe); owner agreed 2026-10-18 |
| stretch | Honeytoken canary (separate module behind a flag) | — | not started |

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
  enigma.py       Key Enigma: KeyRing / key leases; EnigmaKeySource (rotation, drain, fail-closed)
  custody/        Key Enigma management-key custody: ManagementBackend protocol; openrouter.py (fenced key-management client); vault.py + passphrase.py (passphrase vault, `python -m masqai.vault`); device.py (ESP32 backend, pairing, `python -m masqai.device`)
  static/         the GUI (vanilla JS): ui, app, context, security, mapping, config
run_gateway.py    CLI: --config, --playground; prints the token URL
firmware/esp32/   Key Enigma device firmware (MicroPython): enigma_dev/ (pure logic + hw.py adapter), main.py, bench/ (bench-only app, fake OpenRouter, driver, self-test)
tests/            unit + end-to-end tests; tests/injection/ (fixtures + runner)
eval/             the Daytona harness (see eval/README.md)
playground/       six agent workspaces + the untrusted relay
web/              the public site (Next.js, static)
scripts/scan_repo.py   detectors over the repo (CI)
```
