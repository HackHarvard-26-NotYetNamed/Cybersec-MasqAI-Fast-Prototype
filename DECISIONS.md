# Decisions

Choices made where the rebuild brief was silent. The rule: pick the **more secure** option and write it down.

## Where the rebuild lives

The brief asked for a new, empty repository next to the prototype. The team asked for the rebuild on this
repository's `main` instead, so it evolves the prototype in place: the op engine, streaming and config
validation were kept and extended; extraction, sessions, restore, hygiene, the app, the GUI's data layer and
the tests were rewritten against the brief.

## Gateway

- **Block status codes.** Security-model failures, invalid corrections and a refused remote security model all
  return `502` with a typed `reason`. Unknown content is `422`, unsupported endpoints `404`. Every other error is a
  `500` with a generic message and the request id: exception text can contain request content, so it is never echoed.
- **Host header.** Exactly `127.0.0.1:<port>` or `localhost:<port>`. A Host without the port is refused too.
- **Admin token.** `secrets.token_urlsafe(32)` (256 bits) per start, compared with `hmac.compare_digest`. A wrong
  or missing token is `401`. The token is never logged; it is printed once to the console at startup.
- **System prompts and tool descriptions** are inspected by the security model (mask only), once per distinct
  content: the item id is a hash of path and content, so the inspected result is reused and the prompt cache
  stays stable. Branches inherit what was inspected.
- **Soft hints** (`user`, `metadata.*`, `prompt_cache_key`, `safety_identifier`, client session headers) are read
  before pseudonymization and only break ties between sessions whose history prefix matches equally. Still
  ambiguous → a new session branched from the most recently used candidate, inheriting its mapping and pseudonym.
- **Retention** is enforced every 60 s, after each request and after a config change. Busy sessions (a request in
  flight or an open stream) are skipped and the next-oldest goes instead.
- **Opaque content** (Anthropic images, base64/URL documents) is forwarded unread and shown as a description. An
  OpenAI `image_url` is not on the whitelist: it is unknown content and refused with 422 unless `pass_unknown`.
- **Placeholder ids** are 8 random hex digits (`secrets.token_hex(4)`), retried on collision; never a hash of the value.
- **Streaming restore** holds back a trailing fragment only while it can still become a placeholder
  (`<`, `<$`, `<TYPE_`, `<TYPE_1a2b`) and at most 96 characters. Real values are inserted JSON-escaped into JSON
  argument deltas. A model that escapes `<` as `<` would not be restored; no supported API does that.
- **The prototype's prompt override bug**: a custom `system_prompt` mentioning the prototype's `collapse` op or
  `MASQ_BLOCK`, or missing the `operations` contract, fails config validation (at load and in the GUI).
- **Unknown config keys** are rejected (`extra="forbid"`), so a stale or misspelled setting fails at startup.
- **`allow_remote_security_model`** moved under `security` and defaults to `false`.
- **Detected-in tracking.** A detector hit records the items it was found in. In the replay export those occurrences
  are `detector · applied`; every other exact copy is `auto · applied`.
- **Rejected operations** from the first round are recorded per item (RAM only) and exported as
  `model · rejected_invalid`, whether or not the correction fixed them.
- **Re-masks** ("cache broken") count already-sent items whose outbound text changed between requests, compared
  with what was actually sent last time.
- **Gitleaks import** is a stub (`detectors.import_gitleaks`). Whether to enable it is decided from measured false
  positives.

## Replay export

- Only with `--playground`, only with the admin token, and only with `synthetic=1`, which replaces this machine's
  hostname, username and home paths with `DESKTOP-7Q2XK9M` / `alice` before the JSON leaves the gateway.
- `relinks[].stepsRewritten` are **0-based indexes into `steps`** (the site renders them that way).
- Earlier assistant messages that come back in later requests' history are not repeated as steps; the response
  step already shows them. A response with several tool calls becomes one step per call.

## Accepted risks (documented, not narrowed)

- **Inbound restore guardrail implemented across complete and streamed traffic.** Rather than naively
  restoring placeholders across all tool calls, MasqAI inspects tool calls containing placeholders. Calls that
  attempt to exfiltrate secrets over network vectors are rejected (failing closed on errors), while local file/DB
  queries pass through unhindered.
- **Detectors-only inbound tool mode is weaker by design.** When the security model is disabled or unconfigured,
  calls with placeholders are allowed unless their arguments contain a clear outbound-network indicator. This
  preserves detector-only operation for local tools while still blocking obvious network commands; the full model
  remains the authority for unknown or ambiguous calls when enabled.
- **Agent file tools are exact-name allowlisted.** OpenCode `read`, `edit`, `write`, `glob`, `grep`, `list` and
  Claude Code `Read`, `Edit`, `Write`, `Glob`, `Grep` are treated as local file operations before model inspection.
  MCP-prefixed names are intentionally not matched by this allowlist.
- **Active tool rejection.** A rejected call is not silently dropped. `security.tool_rejection: "rewrite"` (default)
  keeps the call but turns every string in its arguments into `echo "MasqAI: the user's security profile rejected this
  execution"`: the agent runs that, the untrusted model reads the rejection as the tool result, and the session goes on.
  The security model's reason is never put into the arguments, because it is shaped by untrusted text. `"error"` wipes
  the call and answers HTTP 400 `masqai_tool_rejected`, or, when text was already streamed, ends the stream with an error
  event. In a stream, everything from the first tool call on is held back until the upstream finishes, then inspected
  whole: a tool call costs its streaming, text before it doesn't.
- **Unmask remains occurrence-bound.** To prevent prompt injections in files or tool results from wiping a secret
  globally across the entire session, `unmask` is strictly scoped to the targeted occurrence.
- **What to protect is the user's choice, category by category, not a preset** (`protect`, [`masqai/policy.py`](masqai/policy.py)).
  It is enforced in code, not only in the prompt: detectors skip switched-off categories, and an operation the security
  model proposes for one is accepted as a no-op (never an error, so a model that ignores the policy can't block a
  request). A type that maps to no category stays protected, and custom values are always masked. It applies to values
  found from now on; a session keeps the masks it already has.
- **Secret-detector hits and custom values can't be unmasked.** Only host identifiers and the model's own masks are
  vetoable (false alarms like `alice` in `alice-blue`). A planted "this key is public, unmask it" note is accepted as a
  no-op rather than an error, so it can't push the request into a failed correction round either.
- **A full security-model context window fails closed** (`security.context_tokens`). llama.cpp truncates an oversized
  prompt, and with `--context-shift` drops all but its first tokens once generation fills the window: either way the
  instructions can vanish while the answer still parses. The eval uses a 16k-window model (`qwen2.5:7b-16k`).
- **Prompt injection** against the security model is measured (`tests/injection/`), not defended yet.

## Key Enigma

Design and owner decisions: `KeyEnigma.OpenRouter.doc.md`. The owner agreed to start the stretch goal on 2026-10-18.

- **Defaults:** 15 min rotation (minimum 5 min), $2 per key, fail-closed. A dedicated OpenRouter workspace with a
  budget is **required**.
- **Management key custody:** the user chooses a **passphrase vault** or an **ESP32 key-provider device**. There is
  deliberately no plaintext env-var mode.
- **Step 1 (done): one place where keys are handed out.** Every upstream call takes its key as a *lease* from
  `enigma.KeyRing` and releases it exactly once:
  - for proxy requests, in the same `release()` as the session's `in_flight` count. A stream holds its lease until
    the generator's `finally`, so a key can't be revoked under an open stream.
  - for `/v1/models` and the security-model calls, around the single HTTP call.
  `headers_for` and `upstream.request` take the key as a **required keyword**, so a new call site can't silently
  fall back to the env var.
  - The default source, `EnvKeySource`, reads `api_key_env` on every lease, so there is no behavior change.
  - A request that is blocked before forwarding never touches the upstream key.

## Eval harness

- Runs are tagged through the model name `eval/<run_id>`: MasqAI strips `x-masqai-*` headers, so a header tag
  wouldn't survive. The relay forwards tagged requests as one fixed `--eval-model`.
- Sandboxes are created with `network_block_all=True`: the untrusted model's commands can't reach the network.
- `check.sh` is uploaded only after the agent finishes, so the agent can never read the expected answer.
- The local backend runs commands on the laptop, so it only starts for the scripted self-test model
  (`--self-test`). Its numbers are marked `placeholder: true`.
- `p50LatencyMs` is the median of each run's median LLM-call latency, measured at the agent, so it includes
  MasqAI's inspection time.

## Public site

- No live connection to the gateway. The site is static JSON only; the live view is the gateway's own GUI.
