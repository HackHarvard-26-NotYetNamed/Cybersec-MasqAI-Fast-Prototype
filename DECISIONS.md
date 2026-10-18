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
- **Step 2 (done): the management-key client is fenced in** (`masqai/custody/`).
  - It uses its own `httpx` client, fixed to `https://openrouter.ai`. Only an allowlist of management requests can be
    made, so the management key can't be sent to an inference endpoint by mistake.
  - Redirects are not followed, and `trust_env=False` ignores proxy and CA settings from the environment. Key hashes
    and workspace ids are validated before going into a URL, and error text is redacted.
  - The backend, not the caller, builds key names, so nothing can be minted or cleaned up outside
    `masqai-enigma-<instance_id>-`.
  - **A minted key is checked against what was asked for.** If OpenRouter reports a later expiry, a higher limit or a
    different workspace, the key is revoked at once and not used. The more secure option: those values are the only
    hard limits on a leaked key.
  - `limit_reset` is always `null`, so a thief's budget never refills.
  - A key probe that gets neither 200 nor 401/403 raises an error instead of guessing "valid" or "dead".
- **Step 3 (done): rotation.** `EnigmaKeySource` mints the next key 60 s ahead, validates it, swaps it in at the
  jittered interval end, drains the old key, then revokes it.
  - **The lease enforces the deadline, not only the background task.** After the deadline the old key gets no new
    leases: the lease swaps to the waiting successor or answers 503. A stalled or crashed rotation task therefore
    can't extend a key's life.
  - A key's interval is capped so that interval + drain + skew margin fits inside the `expires_at` OpenRouter
    actually granted.
  - **The first key is ready before traffic.** Startup fails closed if no first key validates; there is no
    fallback to the env key in `closed` mode.
  - **Keys are masked from mint until confirmed dead.** Standby and revoked-but-maybe-alive keys count as secrets,
    not only the active key.
  - Shutdown revokes every key that may still work.
  - Key values and full hashes never appear in `repr`, logs, events or the snapshot. They show only labels and
    8-character hash prefixes.
- **Step 4 (done): failure handling.**
  - `open` is still bounded: a key never takes a lease past `expires_at − drain − margin`, and a rejected key never
    overstays.
  - A key revoked behind our back (401) **may have leaked**, so it is revoked immediately without waiting for its
    streams. A key that only hit its spend limit drains normally.
  - At most one retry per request. It happens only when the upstream rejected *our key* and a fresh key is ready,
    and only before any byte reached the client.
  - The emergency cap (3 per 10 min) fails closed for the rest of the window. An attacker who can force 401s gets
    an outage, not unlimited minting.
  - Startup cleanup runs before the first mint. A refused management key fails startup; other cleanup errors don't.
- **Step 5 (done): our keys are always masked**, even when the user switches off the credentials category. They
  are the gateway's own secrets, not the user's data.
  - They come from RAM (`KeyRing.known_secrets()`), never from `custom_values`, which `/api/config` shows.
  - The status API shows labels and hash prefixes only.
- **Step 6 (done): passphrase custody.** The vault (`masqai/custody/vault.py`) is AES-256-GCM under an
  Argon2id(256 MiB, t=3, p=4) key. Every header field is authenticated as associated data.
  - **The Argon2 cost has a floor (64 MiB) and a ceiling (1 GiB), and the field set is exact.** Both are checked
    before any work. A file edited to make guessing cheap, or to make unlocking hang, is refused as malformed, not
    tried.
  - The stated management-key expiry is inside the authenticated header, so it can't be moved to silence the
    warnings.
  - Passphrases are NFC-normalized, so the same passphrase typed on another keyboard or OS still opens the vault.
  - **Secrets are typed, never passed.** `seal`, `verify`, `repass` and the gateway read them with `getpass`, and
    only on a real terminal. Without one they refuse, since `getpass` may otherwise echo. No argument or
    environment variable carries a secret.
  - `seal` refuses an existing vault, an inference key (`is_management_key` must be true), a passphrase under 14
    characters, and one that contains the key or is part of it.
  - Written atomically to a temp file in the same folder. The ACL is owner-only with inheritance removed
    (`icacls /inheritance:r`) on Windows, and the mode is 0600 on POSIX. This is best effort and warns rather than
    fails, since the encryption is the protection.
  - **Startup checks the backend before touching anything.** The management key, the workspace and its budget are
    checked first. If any is not ready, nothing is cleaned up or minted.
  - The management key is masked as `ADMIN_KEY`, always, in content and logs. It is wiped from its `bytearray` when
    the gateway stops, and the management client drops its reference and refuses further calls. Python may still
    hold copies elsewhere, so the guarantee is "only in RAM".
  - **A rotating provider never falls back to its env key.** `create_app` refuses a provider with `key_enigma`
    enabled but no rotating source. The base URL must be `https://openrouter.ai`, so a rotated key can't be sent to
    another host. The design's optional bootstrap fallback to `api_key_env` under `open` is not built.
  - **Key Enigma settings are fixed at startup.** The backend was opened for them, so the config API refuses any
    change to a `key_enigma` block, and to a rotating provider's base URL or name. The GUI carries the block
    through unchanged.
  - `run_gateway.py` opens every backend before uvicorn starts and passes `workers=1` explicitly.
- **Steps 7–8 (done 2026-10-18; bench with FAKE keys): device custody.** The management key lives only on the ESP32
  (`firmware/esp32/`). The host holds a pairing file with the frame key and the unlock secret, never the key.
  - **The device decides, the host asks.** Names, expiry (from OpenRouter's TLS-authenticated `Date` header, never
    the host's clock or NTP), the per-key limit, rate limits, the live-key cap and the revoke scope are enforced in
    firmware.
  - **Over-cap requests are refused, not clamped.** A gateway asking for more than the device allows fails at
    startup (`check_rotation`), not silently with shorter keys.
  - **Rate limits survive reboots.** They are computed from the journal in flash, not from RAM.
  - **A mint whose answer was lost still counts as live** until its expiry, since the key may exist.
  - **Frames are MACed over the exact bytes sent**, with a direction tag, a rising counter and a fresh session per
    HELLO. **Every HELLO relocks the device**, so a new process on the port can't inherit an unlocked session.
  - **Secrets on the wire are encrypted** under a per-session key, on top of the MAC. Enrollment uses an X25519
    exchange plus a 6-digit code a person compares; the CLI asks for the management key only after the codes match.
  - **There is no op that returns a secret or a file.** Unknown ops are refused. The command loop catches everything
    and reports only the exception type.
  - The serial transport opens with DTR/RTS deasserted and never toggles them (§13.2).
  - **Bench-only exceptions (owner decisions, 2026-10-18):**
    - A TCP link, because there is no USB-TTL adapter.
    - A one-shot `/enigma/bench_enroll` file instead of holding BOOT.
    - Both live only in `firmware/esp32/bench/` and the `tcp://` transport, which prints a warning wherever it is
      used. Production `main.py` serves UART2 only.
  - The bench uses only FAKE keys: a LAN fake OpenRouter over TLS 1.2, with a throwaway CA and a certificate for
    `openrouter.ai`. A run with a real management key waits for step 9.
  - **Memory on a no-PSRAM ESP32 (§13.6).** The board's USB cable carries no data, so reflashing a frozen build was
    not possible; the owner chose to split and slim the firmware instead (2026-10-18):
    - Enrollment code and X25519 load only in an enrollment window and are unloaded after it.
    - `heap.pregrow()` grows the Python heap once, early, by 34 KB, by briefly holding system heap with a UART2
      receive buffer. Measured trade-off: 45 KB starved TLS, 26 KB starved Python in an enrollment session.
    - The more secure choice where it mattered: a TLS call is **refused** (`NETWORK`, not sent) when either heap is
      short, instead of being attempted; a collapsed system heap **resets** the production board, which relocks it
      (fail-closed). The bench app stops instead of resetting, so OTA stays reachable.
    - A frozen MicroPython build, or a board with PSRAM, is the recommended production fix.
  - **Command timeout 45 s** (was 20 s): on the bench Wi-Fi about 1 TLS call in 20 took 7–15 s, and a REVOKE can be
    two calls.
  - The ESP32-OTA launcher is the owner's and is not modified (owner rule: it is the only way to reach the board).
    Every bench `/app.py` waits 5 s before doing anything (owner rule).
  - Not built: the optional passphrase wrap of the pairing file (§13.3).

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
