# Running MasqAI

The gateway runs on your machine, binds to `127.0.0.1` only, and keeps all state in RAM.

## Start

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
ollama pull qwen2.5:7b                               # the default security model (local)
cp masqai.json.example masqai.json
export OPENROUTER_API_KEY=sk-or-v1-...               # PowerShell: $env:OPENROUTER_API_KEY = "..."
python run_gateway.py [--config masqai.json] [--playground]
```

On every start the gateway generates a fresh admin token and prints it once:

```
  MasqAI http://127.0.0.1:8787  (agents: http://127.0.0.1:8787/v1)
  GUI: http://127.0.0.1:8787/#token=…
  MASQAI_ADMIN_TOKEN=…
```

Open the GUI URL. The page moves the token from the URL into sessionStorage. Every `/api/*` call needs it as
`x-masqai-token`; the agent endpoints (`/v1/*`), `/` and `/static/*` don't. The token is never written to disk.
`--playground` enables the replay export (it contains raw values; demos only). An invalid config fails at
startup with the field that is wrong, instead of failing every request later.

Point the agent at `http://127.0.0.1:8787/v1` (OpenAI style) or `http://127.0.0.1:8787` (Anthropic style).
Send `x-masqai-session: <id>` if your agent can; otherwise sessions are matched by history.

## Endpoints

| Endpoint | Behavior |
|---|---|
| `POST /v1/chat/completions`, `/v1/responses`, `/v1/messages` | sanitize, forward, restore tool-call arguments (streaming or not) |
| `POST /v1/messages/count_tokens` | sanitize (it sends the full context), forward |
| `GET`/`HEAD /v1/models[/…]` | the only unsanitized passthrough |
| any other `/v1/*`, including trailing-slash variants | `404 masqai_unsupported_endpoint`, nothing sent |

Fail closed, nothing sent upstream:

| Event | Response |
|---|---|
| security model error, timeout, invalid JSON, or invalid after one correction round | `502` (`reason`: `security_model_failed` / `invalid_correction`) |
| security provider not on loopback and `allow_remote_security_model` is false | `502` (`remote_security_model_refused`), refused before anything is sent |
| unknown content type (e.g. an OpenAI `image_url`) with `pass_unknown: false` | `422`, before a session or trace exists; says where and what type, never the content |
| unsupported endpoint | `404` |

Errors returned to clients never echo exception text; details are in the console and on the Security tab.

## Configuration (`masqai.json`)

See [`masqai.json.example`](masqai.json.example). Unknown keys are rejected at load. Highlights:

- **providers**: `api_key_env` is an environment variable **name**, never the value. The names referenced at startup
  are frozen: the GUI may reassign them between providers but not add new ones.
- **routes / default_route**: model alias → provider and upstream model.
- **pass_unknown** (default `false`): forward content MasqAI can't inspect raw, with a warning, instead of 422.
- **security**: `provider`, `model`, `api_format` (`openai`/`anthropic`), `allow_remote_security_model` (default
  `false`: only `127.0.0.0/8`, `::1` or `localhost`, no DNS lookup), `timeout_s`, `context_mode` (`recent`/`full`),
  `recent_items`, `nearest_ops`, `op_context_lines`, `auto_mask` (`auto` or `auto_veto`, the default: the model may veto
  a wrong automatic mask), and `system_prompt` (empty = the built-in [`masqai/prompts/security.md`](masqai/prompts/security.md);
  a prompt written for the prototype's `collapse` op is rejected).
- **detectors**: `detect_host_identifiers` (hostname, OS username, home paths), `custom_values` (names, handles, emails
  to always mask), `rules_dir` (rule tables, default [`masqai/rules`](masqai/rules)).
- **headers**: blocklist mode by default. Always dropped: the client's credentials, `x-masqai-*` and hop-by-hop headers.
  The default blocklist also drops cookies, other providers' key headers, `x-stainless-os/-arch/-runtime/-runtime-version/
  -package-version/-lang` (`-retry-count` and `-timeout` pass), client session ids (read locally as hints first),
  `x-forwarded-*`, `x-real-ip`, `forwarded`, `via`, `http-referer`, `x-title`. `user_agent` (default `masqai/0.2.0`)
  replaces the client's User-Agent; empty forwards the client's own.
- **retention**: `idle_ttl_h` (12) and `max_sessions` (50, LRU). Busy sessions are never evicted.

`user`, `metadata.user_id`, `safety_identifier` and `prompt_cache_key` are always replaced with a per-session
pseudonym (`masq-` + 128 random bits). Other `metadata` keys pass.

## The GUI

| Tab | What it shows |
|---|---|
| Context | the dual-reality inspector: raw vs. sent, per item; who masked what (detector, automatic copy, security model), vetoed and left-as-is copies, hidden and replaced intel, opaque items, relinks and the "cache broken" count |
| Security | every security-model call: its exact input, raw answer, each operation ✓/✗ with its error, the correction round, why a request was blocked |
| Mapping | the entity table (token, type, class, origin, uses, linked-to, real value) and Forget session |
| Config | a live editor with inline validation, the security prompt, the remote-model switch, env names as a dropdown |

The GUI shows raw values to you, the local user. Use the playground or a demo account before sharing your screen.

## Control API (`/api/*`, admin token required)

`GET /api/state` · `GET /api/sessions/{id}` · `POST /api/sessions/{id}/forget` · `GET /api/security` ·
`GET /api/events` (SSE: `trace`, `session`, `forget`, `config`, `warning`, `forwarded`; read it with `fetch`, since
`EventSource` can't send the header) · `GET`/`POST /api/config` · `GET /api/config/meta` · `GET /api/env/{name}`
(startup names only, never the value) · `GET /api/sessions/{id}/replay?synthetic=1` (only with `--playground`; streams the
public site's replay JSON with host identifiers replaced by fake ones; the gateway never writes it to disk).

Every request that reaches the upstream emits a `forwarded` event with the SHA-256 of the sanitized body. The
eval harness uses it to count requests.

## Logs

Logs carry routing decisions, request shapes, timings and statuses, never raw context. Upstream error bodies
are masked with the session's known values before they are logged. `MASQAI_LOG_LEVEL=DEBUG` adds the
*sanitized* outbound body, which is what the untrusted model sees anyway. The filesystem is untrusted:
don't keep DEBUG output.

## Verification

```bash
python -m pytest -q                       # core, proxy end to end, hardening, injection scoring, eval harness
python scripts/scan_repo.py               # MasqAI's detectors over the repo itself
python -m tests.injection.run_injection --config masqai.json --runs 20   # needs the security model
```

Playground walkthrough (six agent tasks against an untrusted relay): [`playground/README.md`](playground/README.md).
`playground/tools.py` needs `MASQAI_ADMIN_TOKEN` (printed at startup) to change the running config.
