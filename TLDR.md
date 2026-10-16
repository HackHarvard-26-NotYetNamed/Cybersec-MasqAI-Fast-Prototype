# MasqAI: TL;DR for the team

> **"Your LLM key is a two-way mirror. MasqAI makes it one-way."**
> HackHarvard 2026, Cyber-sec track. Read this in 3 minutes, then go to `playground/README.md` for the demo.

## The problem (our pitch hook)

One of our LLM API keys leaked. Instead of only revoking it, we watched the traffic going through it. Coding agents using that key were sending:

- OS and hardware fingerprints
- internal host paths (e.g. the path to an app's production database)
- Telegram usernames and emails

From that single key we got fingerprints of about 40 other keys, all going through one self-hosted relay.

**What we learned:** whoever runs the LLM endpoint sees everything your agent sends. That includes not just the key, but all the context too.

## What we built

**MasqAI** is a local gateway written in Python and FastAPI. It runs on `127.0.0.1:8787` and sits between your coding agent (e.g. OpenCode) and an LLM endpoint you don't trust.

```
Agent ──► MasqAI (localhost) ──► untrusted relay / LLM provider
            │ 1. regex detectors (keys, JWT, emails, PEM, hostname, username, home paths)
            │ 2. local "security LLM" (Ollama qwen2.5:7b) finds what regex misses
            │ 3. mask:     secret        → <TYPE_id>   (reversible, mapping kept in RAM)
            │    collapse: noisy tool output → …[MASQ_BLOCK: summary]…  (lossy, saves tokens)
            ◄── response: placeholders in TOOL CALLS are restored to real values,
                so the agent still runs `sqlite3 C:\real\path.db` correctly
```

- **Fail closed:** if the security model errors or returns invalid output (after one correction retry), the request gets HTTP 502 and nothing is sent upstream.
- **Dual-Reality Inspector (GUI)** at http://127.0.0.1:8787. It shows the raw and sanitized context side by side, the mapping table, a step-by-step trace of each security pass, and a live config editor. This is the visual centrepiece of the demo.
- **Supported APIs:** OpenAI `/v1/chat/completions` and `/v1/responses`, and Anthropic `/v1/messages`. Streaming and non-streaming both work.

## Status

| Done (77 unit tests pass) | Design only, do NOT claim as working |
|---|---|
| Masking, collapsing, partial forms (`<$TYPE_id>`), relink, retroactive re-masking | **Key Enigma** (automatic key rotation) |
| Session tracking with rollback and branching | Paranoid/Balanced/Eco presets |
| Tool-argument restore (streaming too) | Browser plugin, shared multi-user router |
| GUI with 3 tabs, fail-closed, localhost-only hardening | Restoring placeholders in chat **text** (only tool args are restored) |

## Run it (PowerShell, from the repo root)

```powershell
python -m venv .venv; .\.venv\Scripts\python -m pip install -r requirements.txt
$env:OPENROUTER_API_KEY = "sk-or-v1-..."
ollama pull qwen2.5:7b
.\.venv\Scripts\python run_gateway.py            # GUI: http://127.0.0.1:8787
.\.venv\Scripts\python -m unittest discover -s tests   # 77 tests
```

To point an agent at MasqAI, use base URL `http://127.0.0.1:8787/v1` with any dummy API key.

> **Fix this before demoing:** the local `masqai.json` (line 32) has an **old `system_prompt`** that asks for the old `{"entities","rephrase"}` format. The code now expects `{"operations":[...]}`, so requests will likely all fail with 502. Clear that field (in the GUI Config tab, or in the file) to use the built-in prompt. The playground config is fine.

## The demo (full script: `playground/README.md`)

Use 3 terminals: **relay** (`playground/relay.py`, :8788, shows the "attacker view"), **MasqAI** (`MASQAI_CONFIG=playground\.state\masqai.playground.json`), and an **agent** (OpenCode inside `~\masq-playground\ucN-*`). Run `playground\setup.py` first to generate the workspaces and synthetic secrets.

| Use case | What the audience sees |
|---|---|
| UC1 env dump | `Get-ChildItem Env:` gets collapsed and host details masked. Fewer bytes sent |
| UC2 prod DB path | The relay only sees `<PATH_x>`, yet the agent's `sqlite3` call still runs on the real path |
| UC3 hard-coded key | The agent moves the key into `secrets.json`. The real key is on disk; the relay saw only a placeholder |
| UC4 partial key, then full key | Shows linking the two and re-masking earlier messages |
| UC5 Telegram identity from git blame | Depends entirely on the LLM (riskiest, rehearse it) |
| UC6 fail closed | `tools.py break-security` → the agent gets a 502 and the relay receives **0 requests** |

Show both tabs side by side: :8787 is our view, :8788 is the attacker's view. Run each use case with `start-opencode.ps1 -Provider relay` first as the unprotected "before" baseline.

**Rehearsal rule:** a use case goes on stage only if it scores 10/10 runs with task OK, 0 leaks and 0 unexpected 502s.

## Be honest with judges

- Detection isn't perfect. A 7B local model misses things, so the goal is **lower** exposure, not zero. See "What we give up" in `README.md`.
- The GUI shows raw secrets by design (it's local). **Only use the playground's synthetic secrets on screen.**
- Ethics: defensive only. We never show real third-party identities or keys.

## Where to read more

- `README.md`: full design and trust model
- `RUNNING.md`: the most accurate description of what the code does
- `Design-QnA.doc.md`: design decisions
- `playground/README.md`: demo playbook
- Code: `masqai/app.py` (proxy), `sanitize.py` (pipeline and prompt), `ops.py` (masking engine), `streaming.py` (restore)
