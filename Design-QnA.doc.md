\# Design Q\&A Document



\*\*Q: How should the gateway work out which session a request belongs to, using only the stream of requests? Reason: neither the OpenAI nor the Anthropic API has a standard session ID, and agents resend the full history on every call, compact it, and branch it.\*\*

\*\*A:\*\* Hybrid: hints, then prefix



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



\*\*Q: You said the remote model should never emit `<$X>`, but it may copy it from context. If `<$X>` appears in a tool call, what should happen?\*\*

\*\*A:\*\* Restore `<$X>` to canonical too

> \*Clarified (2026-10-16):\* a `<$X>` (or a linked entity's token) restores to the canonical value of the entity it ultimately links to.



\*\*Q: Anthropic `/v1/messages/count\_tokens` also sends the full context upstream. How should it be treated?\*\*

\*\*A:\*\* Sanitize `count\_tokens`, pass others



\*\*Q: Which API format for the security model?\*\*

\*\*A:\*\* OpenAI or Anthropic format



\*\*Q: Which deterministic detectors should seed the mapping table?\*\*

\*\*A:\*\* Patterns + host identifiers + user list


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

> \*Consequence to confirm when implementing:\* with the default `pass\_unknown: false`, image inputs over the OpenAI formats are refused. Anthropic `image` is whitelisted opaque, so it still passes.



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



\## Tier C: held for now

Not decided yet; revisit later:
\- session-hint merging across clients;
\- LLM inspection of system prompts and tool descriptions;
\- broader detector coverage (AWS secret keys, Stripe, Google, Slack, `password=`, entropy);
\- a deterministic check after the LLM against prompt-injected empty answers;
\- masking short or in-word values by entity type;
\- narrowing placeholder restore in tool calls;
\- limiting `/api/env/{name}`.
