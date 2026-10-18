# Key Enigma for OpenRouter: design (Q&A)

Status: **design only, not built.** This document is the reference for the first Key Enigma provider.
It follows the README section "Key Enigma: continuous key rotation", the brainstorm doc section 5, and the PLAN.md
stretch rule ("separate module behind a flag").

Facts about OpenRouter come from its public docs (Management API keys, `POST /api/v1/keys`, Limits), read 2026-10-18.
Anything the docs do not state is marked **(unverified)** and is measured by the probe script in §11.

Decisions made by the owner (2026-10-18):
1. The defaults are accepted: 15 min interval, $2 per key, fail-closed.
2. A **dedicated OpenRouter workspace is required**.
3. **Sealed storage is in scope now.** The user can choose either a **passphrase vault** or a **key-provider device**
   (an ESP32 running MicroPython). See §3 and §13.

---

## 0. Summary

- A long-lived **management key** (OpenRouter's name for the admin key) can create and delete keys, but cannot call
  models. It is kept in one of two places, chosen in config:
  - **`passphrase` mode:** an encrypted vault file on disk. It is decrypted only into the gateway's RAM, after the
    passphrase is typed at startup.
  - **`device` mode:** an ESP32 key-provider device. The key **never reaches the host at all**: the device makes the
    management calls itself and hands the gateway only short-lived inference keys whose limits are capped in firmware.
- Every *interval* (default 15 min, with jitter) the gateway creates a new **inference key** and checks that it works.
  It then sends all new requests to that key. The old key **drains**: it waits until its last in-flight request or
  stream ends, is **deleted**, and then is **probed** until OpenRouter rejects it.
- Every inference key is created with **two limits set at creation**:
  - `expires_at`: the key dies on OpenRouter's side even if the gateway crashes or a delete fails.
  - `limit`: a USD cap on what a leaked key can spend.
- No inference key is ever written to disk. After a restart, keys left over from an earlier run are found and deleted.
- Each key value, and the management key, is fed to the deterministic detectors, so none of them can be sent upstream
  in request content.

---

## 1. Scope

**Q: What exactly is being rotated?**
The OpenRouter **inference key** (`sk-or-v1-…`) that MasqAI sends as `Authorization: Bearer …` on calls to
`https://openrouter.ai/api/v1/*`. Today it comes from `ProviderConfig.resolved_key()` (`masqai/config.py:107`), which
reads an env var on every call.

**Q: Which process runs Key Enigma?**
The process that holds the upstream key. In the direct setup (`OpenCode -> MasqAI -> OpenRouter`) that is the
**MasqAI gateway**, and that is the only setup Key Enigma supports in v1.

**Q: What about the playground, where `relay.py` holds the key?**
The relay simulates an *untrusted third-party* relay that you do not control. In that setup there is nothing for us
to rotate, because the relay's key belongs to its operator.
For demos we add a playground config that routes the gateway **directly** to OpenRouter (no relay), with Key Enigma
switched on. The relay setup stays unchanged.

**Q: Does it rotate the security-model key too?**
Yes, if the security model's provider is the same OpenRouter provider entry, because both use the same key source.
They are covered at `sanitize.py:267` and `sanitize.py:324-336`. Each provider entry gets its own rotation. Only
providers with `key_enigma` switched on are rotated.

**Q: Which key types are out of scope?**
BYOK provider credentials, OAuth/PKCE user keys, and keys owned by other tools on the same account. Key Enigma only
ever touches keys it created itself, identified by name prefix (§6).

---

## 2. The OpenRouter API we depend on

**Q: What do the docs promise?**

| Need | Endpoint | Notes from the docs |
|---|---|---|
| Create | `POST /api/v1/keys` | Body: `name` (required), `limit` (USD, optional), `limit_reset`, `expires_at` (ISO 8601 UTC **with seconds**; minute precision is rejected), `include_byok_in_limit`, `workspace_id`. Returns `201` with `key` (plaintext, **shown once**) and `data.hash`. |
| Delete | `DELETE /api/v1/keys/{hash}` | Permanent. |
| Disable | `PATCH /api/v1/keys/{hash}` with `{"disabled": true}` | Our fallback when delete fails. |
| List | `GET /api/v1/keys?offset=N` | Pages of 100. Used to clean up after a restart. **Lists only the default workspace unless `workspace_id` is given**, and skips disabled keys unless `include_disabled=true` and expired keys unless `include_expired=true` (OpenAPI spec, re-checked 2026-10-18). Cleanup passes both `workspace_id` and `include_disabled=true`. |
| Get one | `GET /api/v1/keys/{hash}` | `usage`, `limit_remaining`, `last_used_at`. Used to read final spend. |
| Check a key | `GET /api/v1/key` (with the inference key) | `401` once a key is invalid, disabled or expired. Used to validate a new key and to confirm revocation. |

Other things the docs state:
- Management keys **cannot call completion endpoints**, so a leaked management key cannot be used to run models directly.
- Management keys apply to the whole account and are not limited to one workspace.
- A management key's expiry is fixed when it is created. After it passes, every call returns `401 API key expired`.
- OpenRouter enforces rate limits globally, so "making additional accounts or API keys will not affect your rate
  limits". Rotation therefore neither costs nor gains throughput, and is not a way around limits.

**Q: What is not documented?** All of these are **(unverified)** and measured by §11:
1. Rate limits on the management endpoints themselves.
2. How long a deleted key keeps working (**revocation propagation delay**).
3. Whether `PATCH` can change `expires_at` on an inference key. **Answered by the OpenAPI spec (2026-10-18): no.**
   `PATCH /keys/{hash}` accepts only `disabled`, `include_byok_in_limit`, `limit`, `limit_reset`, `name` and
   `workspace_id`. Nothing in the design depended on it.
4. Whether the account has a cap on the number of keys.
5. Whether rapid create/delete cycles trigger abuse detection.
6. Whether a new key works instantly or needs a short delay (**creation propagation delay**).

---

## 3. The management key

**Q: Where does the management key come from?**
The user creates it on OpenRouter's "Management API Keys" page. On an organization account, only an Organization
Admin can do this. The user should set an expiry on it, as OpenRouter recommends; 30–90 days is suggested.

**Q: Where is it kept? (`custody.mode`, chosen by the user)**

| | `passphrase` | `device` |
|---|---|---|
| Where the key lives | An encrypted vault file on the host. It is decrypted into gateway RAM at startup. | Only in the ESP32's flash. **It never reaches the host after enrollment.** |
| Who calls `/api/v1/keys` | The gateway, using `httpx` | The device, over its own Wi-Fi and TLS |
| What the gateway holds | The management key plus the inference keys | Inference keys only (at most $2 each, about 31 min) |
| Protects against disk theft, backups, a leaked repo | Yes | Yes |
| Protects against an attacker **inside the running host** | **No.** The attacker can read RAM. | **Yes, within limits.** The attacker gets only what the device's rules allow (§13). |
| Protects against physical theft of the device | n/a | **No** on stock MicroPython (§13.7) |
| Startup step for the user | Type the passphrase | Device powered on and connected by 3-wire UART |
| Hardware | none | ESP32 + 3.3 V USB-TTL adapter |

There is **no env-var mode**. Following the DECISIONS.md rule ("pick the more secure option"), a plaintext management
key in the environment is not supported. Tests inject a fake backend instead (§11).

The gateway code does not depend on the mode. Both modes implement one interface, and the rotation state machine
(§4–§8) is identical:

```python
class ManagementBackend(Protocol):
    async def mint(self, *, suffix: str, expires_at: datetime, limit_usd: float) -> MintedKey: ...  # backend adds the prefix
    async def revoke(self, key_hash: str) -> RevokeOutcome: ...  # DELETE, falling back to PATCH disabled
    async def usage(self, key_hash: str) -> float: ...
    async def cleanup(self) -> int: ...                       # delete leftovers from earlier runs
    async def status(self) -> BackendStatus: ...              # healthy?, expiry if known, policy caps
    async def aclose(self) -> None: ...
```

`PassphraseBackend` calls OpenRouter directly. `DeviceBackend` sends the same operations over serial (§13.4).

### 3.1 Passphrase mode: the vault

**Q: What is in the vault file?**
The vault is `custody.vault_path`, by default `~/.masqai/openrouter.vault`. It contains one JSON object:

```json
{ "v": 1, "kdf": "argon2id", "m_kib": 262144, "t": 3, "p": 4,
  "salt": "<16 random bytes, b64>", "nonce": "<12 random bytes, b64>", "provider": "openrouter",
  "created": "2026-10-18T12:00:00Z", "management_expires_at": "2027-01-31T23:59:59Z", "hint": "openrouter management",
  "ct": "<AES-256-GCM ciphertext+tag, b64>" }
```

- The encryption key is `Argon2id(passphrase, salt, m=256 MiB, t=3, p=4)` → 32 bytes. Measured: about 0.15 s on the
  dev laptop (the earlier estimate was 1 s); the cost is the 256 MiB per guess. These parameters are stronger than
  RFC 9106's second recommended setting (64 MiB).
- Every header field except `ct` is bound into the encryption as **associated data**. Changing any of them, for
  example lowering `m_kib` to make guessing cheaper, makes decryption fail.
- Salt and nonce come from `secrets.token_bytes`. A fresh nonce is used every time the vault is re-sealed.
- The file is written atomically (write to a temp file, then `os.replace`). It is restricted to the current user:
  an owner-only ACL on Windows, `0600` on POSIX. This is best effort, because the encryption itself is the
  protection.
- New dependencies: `argon2-cffi` and `cryptography`.

**Q: How does the key get into the vault?**
`python -m masqai.vault seal --provider openrouter`
1. Prompts with `getpass` for the management key, never through command-line arguments or env vars.
2. Checks that the key really is a management key: `GET /api/v1/keys` must return `200`. An inference key gets
   `403` there.
3. Prompts for the passphrase twice. It requires **at least 14 characters** and rejects a passphrase that contains
   the key itself.
4. Writes the vault.

Other commands:
- `masqai.vault verify` decrypts and re-checks the key, without starting the gateway.
- `masqai.vault repass` changes the passphrase.
- `masqai.vault destroy` overwrites and deletes the vault.

**Q: How is it unlocked?**
`run_gateway.py` prompts with `getpass` before uvicorn starts.
- **If there is no TTY, the gateway refuses to start**, failing closed. There is deliberately no
  `MASQAI_VAULT_PASSPHRASE` env var, because that would put a plaintext secret back in the environment.
- 3 wrong attempts → exit. Each wrong attempt costs one Argon2 derivation.
- The decrypted key is kept in a `bytearray` and wiped when the gateway shuts down. Python may keep internal copies,
  for example inside `httpx` header strings, so the guarantee is "only in RAM", not "erased from RAM".

**Q: What if the passphrase is forgotten?**
Nothing important is lost:
1. Delete the management key on OpenRouter.
2. Create a new one.
3. Run `seal` again.
So **no backup of the vault is needed or recommended.**

### 3.2 Device mode: summary

The ESP32 acts as a **key-provider device**. The management key is written to it once (enrollment) and never comes
back out over the serial link. The device:
- calls `POST/DELETE/GET /api/v1/keys` itself over HTTPS, with the server certificate checked;
- hands the gateway only freshly minted inference keys;
- enforces a fixed **policy** in firmware that the host cannot change: the workspace, the maximum per-key limit, the
  maximum expiry, the name prefix, a mint rate limit, and a maximum number of live keys.

The full specification is in §13.

### 3.3 Rules for both modes

**Q: Can the management key ever be sent upstream or exposed?**
It must not be. Four layers enforce that:
1. **Never in a header to an inference endpoint.**
   - In passphrase mode, the management client is a separate `httpx.AsyncClient`. Its base URL is fixed to
     `https://openrouter.ai/api/v1/keys` and it refuses any other path. Probes of inference keys use a different client.
   - In device mode, the host does not have the key at all.
2. **Never in request content.**
   - In passphrase mode, the value is added to `seed_entities()` (`masqai/detectors.py:209`) as a fixed entity of
     type `ADMIN_KEY`, supplied from RAM. It must **not** go through `custom_values`, because those are returned by
     `/api/config`.
   - In both modes, the `openrouter_key` regex (`patterns.toml:28`) catches the `sk-or-v1-` shape as a second net.
3. **Never in logs.** It is added to the value set used by `scrub()` (`app.py:501`). Log lines show only `label` and
   the first 8 characters of `hash`.
4. **Never in config or the GUI.** `/api/config` shows only `custody.mode`, the vault path or serial port, and the
   device ID. `/api/enigma/status` shows labels, states and times.

**Q: What if the management key leaks anyway?**
The answer depends on the mode, and an earlier draft of this document got it wrong. OpenRouter management keys are
**account-wide and not limited to one workspace**, and they can also **edit or delete workspace budgets**. A leaked
management key can therefore mint keys in *any* workspace with *any* limit, and can remove the Enigma workspace's
budget. **A workspace budget does not cap a leaked management key.**

| Mode | How the key could leak | What limits the damage |
|---|---|---|
| `passphrase` | Host compromise while the gateway runs, or a stolen vault plus a guessed passphrase | Only the management key's expiry and your account balance. Keep the account's prepaid balance low, and do not enable auto top-up. |
| `device` | Physical theft and a flash dump (§13.7) | The same as above. A host compromise does **not** leak the key. It only gives the attacker inference keys, and those are capped by device policy **and** by the workspace budget. The host can't change that budget, because changing it needs the management key. |

The gateway also alerts when the key list contains keys with our prefix that we did not create (§6). This works in
passphrase mode. In device mode it is run by the device only if the board has PSRAM (§13.6).
Rotating the management key itself stays manual: create a new key, re-seal or re-enroll, then delete the old key.

**Q: What if the management key expires while running?**
`seal` and `enroll` ask for the management key's expiry date, because OpenRouter may not let a key read its own
expiry **(unverified)**. The date is stored in the vault header or in the device's config.
- The gateway warns in the log and GUI at T-7d and T-1d.
- When a mint returns `401`, rotation stops and the §8 failure policy applies.

---

## 4. Key lifecycle

**Q: What states does an inference key go through?**

```
 MINTING ──ok──> VALIDATING ──ok──> ACTIVE ──interval──> DRAINING ──refcount 0 or drain cap──> REVOKING
    │                 │                                                                         │
    └─fail──> (retry) └─fail──> DISCARDED (delete it)                     ok: DELETED ──probe 401──> DEAD
                                                                          fail: DISABLED / rely on expires_at ──> DEAD
```

- **MINTING:** `POST /api/v1/keys` with name `masqai-enigma-<instance>-<seq>` (§6), `expires_at`, `limit` and
  the required `workspace_id`. In device mode, the device builds the name and the request itself (§13.5).
- **VALIDATING:** `GET /api/v1/key` with the new key must return `200`. This covers the creation propagation delay.
  We retry for up to 10 s with backoff, then discard the key.
- **ACTIVE:** exactly one key per provider is active. New requests take a lease on it.
- **DRAINING:** no new leases. Existing streams continue.
- **REVOKING:** `DELETE`. If that fails 3 times: `PATCH disabled=true`. If that also fails: rely on `expires_at` and
  raise an alert.
- **DEAD:** a probe with `GET /api/v1/key` returns `401`. The time from `DELETE` to the first `401` is the measured
  **propagation delay**, which is logged and fed back into §5.

**Q: When is the next key created?**
Ahead of time: at `activated_at + interval − lead`, where `lead` = 60 s. The new key is already validated when the
interval ends, so the switch takes no time and never blocks a request.

**Q: How is the swap made atomic?**
The active key is one reference, `self._active: KeyRecord`. It is swapped under an `asyncio.Lock` held only for the
swap. A lease reads that reference and increments `record.refcount` in the same synchronous step; there is no `await`
between them, so the asyncio event loop guarantees atomicity. A request therefore holds either the old key or the new
one, never a mix.

---

## 5. Timing: interval, jitter, drain, expiry

**Q: How often do keys rotate?**
`interval_seconds`, default **900** (15 min), minimum **300**. The minimum is there because the management API's rate
limits are **(unverified)**, and minting a key every few seconds looks like abuse.

**Q: Why jitter?**
So that an attacker watching the traffic cannot predict when a key switches. The actual interval is drawn as
`interval × U(1 − j, 1 + j)` with `jitter = 0.2`, using `secrets.SystemRandom()`.

**Q: How long does an old key stay alive?**
It drains until its **refcount reaches 0**, capped at `drain_cap_seconds`. The cap defaults to the upstream request
timeout (600 s, matching the relay's `Timeout(600)` and `upstream_timeout_seconds`), since no request can outlive
that anyway.
After the `DELETE`, the key may still be accepted for the propagation delay.

**Q: What `expires_at` does each key get?**
```
expires_at = now_utc + interval × (1 + jitter) + lead + drain_cap + safety_margin
           = 900×1.2 + 60 + 600 + 120  ≈ 31 min with defaults
```
This is the **hard ceiling** on a key's life, enforced by OpenRouter. A key can never outlive it, whatever happens to
the gateway.
- It is formatted with seconds: `YYYY-MM-DDTHH:MM:SSZ`.
- Times are scheduled with `time.monotonic()`. Wall-clock UTC is used only to compute `expires_at`.
- The 120 s `safety_margin` absorbs clock skew between our host and OpenRouter.

**Q: So what is the exposure window if a key leaks?**
- **Typical:** the time until the next rotation, plus the drain, plus the propagation delay. That is usually under
  about 16 min with defaults, because most requests finish in seconds.
- **Worst case:** `expires_at`, about 31 min.
- **Spend ceiling** inside that window: the per-key `limit` (§7).

**Q: What if a single stream really needs longer than the drain cap?**
It cannot, because the upstream timeout already kills it at 600 s. If a user raises the timeout, the drain cap and
`expires_at` grow with it, since both are computed from the timeout rather than fixed numbers.

---

## 6. Naming, restarts and cleanup

**Q: How do we recognize our own keys?**
Each key gets the name `masqai-enigma-<instance_id>-<seq>`.
- `instance_id` is 8 hex characters from `secrets.token_hex(4)`, generated once per install and stored in config as
  `key_enigma.instance_id`. It is not secret.
- `seq` counts up during a run.
- The `label` shown in the GUI and in exports is `enigma-<seq>`, matching `web/public/data/keys.json`.

**Q: What happens on restart?**
Key values are never persisted, and OpenRouter shows a key value only once. Any key from a previous run is therefore
unusable to us and must be removed.

On startup, in passphrase mode, the gateway:
1. Lists all keys, paging with `offset`, and selects those whose name starts with `masqai-enigma-<instance_id>-`.
2. Deletes each one, falling back to disabling it.
3. Mints and validates a fresh key before the gateway accepts traffic.

In device mode, the device keeps a **journal** of the keys it has minted. The journal holds hashes and expiry times;
a hash cannot be used to make requests. Cleanup deletes the keys listed in the journal, so the device does not need
to list every key on the account, which it may not have the RAM for (§13.6).

No inference key value is written to disk. This also answers README open question 8 ("Keeping the mapping table
across restarts") for Key Enigma: there is nothing to keep.

**Q: What if the gateway is killed with `kill -9` and never restarts?**
The leftover keys die at their `expires_at`, about 30 min later. That is the main reason `expires_at` is mandatory.

**Q: Two gateways on the same account?**
Each install has its own `instance_id`, so neither deletes the other's keys.
Running several uvicorn workers in one install is **not supported**: each worker would rotate on its own. Startup
refuses `workers > 1` when Key Enigma is enabled.

**Q: How do we detect an intruder minting keys?**
At each rotation (cheap: one list call), we compare the keys with our prefix against our in-RAM set. Any unknown key
under our prefix triggers an alert. If `delete_unknown` is set (off by default), it is also deleted.

---

## 7. Money and usage

**Q: How do we cap what a leaked inference key can spend?**
Every key is created with `limit = per_key_limit_usd` (default **$2**, `limit_reset: null`).
- A key that reaches its limit gets `402`/`403` with `limit_source: openrouter_key_limit`.
- The gateway treats that as **"rotate now"** (§8). Normal heavy use therefore just rotates more often, while a thief
  is capped at the limit.

**Q: Isn't a per-key limit going to cut off a legitimate long task?**
No, because rotation is transparent to clients. One edge case remains: a single request whose cost is larger than
the limit fails.
- `per_key_limit_usd` must be at least the most expensive single request expected.
- The config validator warns when it is below $0.50.

**Q: How is spend aggregated across rotations?**
Just before deleting a key, we read `GET /api/v1/keys/{hash}` → `usage` and add it to an in-RAM ledger per provider.
- OpenRouter settles charges shortly *after* a request completes, so the last cents of a key can arrive after we read
  it. We wait for the drain to finish plus 5 s before reading.
- We label the ledger "approximate". The authoritative figure is OpenRouter's activity page or `/api/v1/activity`.

**Q: Is a dedicated workspace required?**
**Yes (owner decision).** `workspace_id` is required whenever Key Enigma is enabled. In passphrase mode, startup
checks the workspace through `GET /api/v1/workspaces/{id}` and its budget through
`GET /api/v1/workspaces/{id}/budgets`. **Startup refuses if the workspace has no budget.** This is a fail-closed
choice; the budget is the reason the workspace is required. In device mode the device runs the same checks at
enrollment and again when it boots.

The workspace gives:
- a **workspace budget** as a second ceiling on spend. It caps every inference key, including keys a compromised
  host obtains through the device. It does **not** cap a leaked management key, which can change budgets (§3.3).
- keys that are clearly separated from the user's own keys in the dashboard;
- guardrails (allowed models and providers) that apply only to Enigma keys.

---

## 8. Failure handling

**Q: What does `failure_policy` mean here?**
It applies when the gateway **cannot get a fresh key** (minting or validation keeps failing):

| Policy | Behavior | Bound |
|---|---|---|
| `closed` (**default**, per the DECISIONS.md rule "pick the more secure option") | When the interval ends without a validated successor, new requests get `503 {"error":{"type":"masqai_key_unavailable"}}`. Open streams finish on the old key. | No key outlives its interval by more than the drain. |
| `open` | Keep using the current key after its interval ends, and keep retrying the mint. | **Still bounded by `expires_at`**: OpenRouter kills the key, and then the gateway acts as `closed`. |

Retries use exponential backoff (2 s → 60 s cap). On `429` we honor `Retry-After`.

**Q: What if an inference call returns `401` with the active key?**
Someone revoked or expired it. OpenRouter may also auto-revoke leaked keys **(unverified)**. The gateway then:
1. Marks the key DEAD and starts an emergency rotation at once. The minimum interval does not apply, but emergency
   rotations are capped at 3 per 10 min to avoid a loop.
2. Retries the request once with the new key, **only if no bytes have reached the client yet**. A `401` means the
   provider did not process the request, so the retry cannot double-charge.
3. Raises a `key_revoked_externally` alert, because it may mean the key leaked.

**Q: What about `402`/`403` with `limit_source: openrouter_key_limit`?**
That means the key's limit is used up. The gateway rotates early, the same way as for `401`, and retries once with
the same "no bytes sent" rule.

Other cases are passed through unchanged, with no rotation:
- `402` with `openrouter_credits`: the account is out of money.
- `402` with `openrouter_in_flight_budget`: transient.
- `403` from a guardrail or workspace budget.

**Q: What if `DELETE` fails?**
1. Retry 3 times with backoff.
2. Then `PATCH disabled=true`.
3. Then leave it and rely on `expires_at`.
Each step is logged. A key that is not confirmed dead appears in the status API as `revoke_failed` until it expires.

**Q: What if the management key gets `401`/`403`?**
It has been revoked or expired, or it lacks permission. Rotation stops, `failure_policy` applies, and a critical
alert is raised. Retrying in a loop would be pointless, so we retry once per 5 min.

**Q: What if OpenRouter is entirely down?**
Inference is down too, so rotation status hardly matters. Mint retries back off, and nothing bad happens; existing
keys die on schedule.

**Q: What if the device is unplugged, crashes or loses Wi-Fi?** *(device mode)*
The gateway's `DeviceBackend` handles it as follows:
- Each command has a 20 s timeout, which leaves room for one TLS handshake plus OpenRouter's response.
- The device is pinged every 30 s.
- When the device can't be reached, it is treated like a failed mint: `failure_policy` applies. With the default
  `closed`, traffic stops when the active key's interval ends.
- The key that is already active **keeps working until its interval ends**. Unplugging the device never cuts a
  stream in progress.
- If the device stays unreachable, old keys can't be deleted. They die on their own at `expires_at`, and the status
  API reports them as `revoke_pending_device`.
- When the device reconnects, the gateway authenticates again (§13.4) and the device clears its journal.
- A device that reboots mid-command can leave a key minted but never delivered to the gateway. The device's journal
  records the key before it is sent, so the next cleanup deletes it.

**Q: What if the clock jumps (laptop sleep)?**
Scheduling uses `time.monotonic()`, which does not count suspended time on every OS **(platform-specific)**. On wake,
we compare the wall clock with the active key's `expires_at`.
- If the key is expired or less than `lead` from expiry, we rotate immediately.
- If the key fails validation, we follow the `401` path.

---

## 9. Code changes in this repo

**Q: Where does the code go?**
In **`masqai/enigma.py`**, a new module. It does nothing unless `key_enigma.enabled` is true (PLAN.md: "separate
module behind a flag").

```python
class KeySource(Protocol):
    def lease(self) -> AbstractContextManager[str]: ...   # sync acquire; refcount++/--
    def known_secrets(self) -> list[tuple[str, str]]: ... # (value, TYPE) for seed_entities/scrub

class EnvKeySource:     # today's behavior: os.getenv(api_key_env), no-op refcount
class EnigmaKeySource:  # rotation state machine; talks only to a ManagementBackend (§3)
```

Supporting modules:

| Module | Contents |
|---|---|
| `masqai/enigma.py` | `KeySource`, `EnvKeySource`, `EnigmaKeySource` |
| `masqai/custody/__init__.py` | The `ManagementBackend` protocol and `load_backend(config)` |
| `masqai/custody/openrouter.py` | `OpenRouterKeys`, a thin httpx client for create, list, get, delete, disable and probe |
| `masqai/custody/vault.py` | The vault format, `seal`/`unseal`, and the CLI (`python -m masqai.vault ...`) |
| `masqai/custody/passphrase.py` | `PassphraseBackend` (vault + `OpenRouterKeys`) |
| `masqai/custody/device.py` | `DeviceBackend` (serial protocol, §13.4) and the CLI (`python -m masqai.device enroll / status / unpair`) |
| `firmware/esp32/` | MicroPython firmware: `main.py`, `boot.py`, `enigma_dev/*.py`, plus `README.md` with flashing steps |

`firmware/` sits outside `masqai/`, because the gateway never imports it.

**Q: Which existing call sites change?**

| Site | Change |
|---|---|
| `upstream.py:40-55` `headers_for()` | Takes the key as an argument instead of calling `provider.resolved_key()`. |
| `app.py:355` (proxy) | `lease = key_source(provider).lease()` before building headers. It is released in the **same `finally` as `release()`**: streaming at `app.py:401-405`, non-streaming at `443-445`. |
| `app.py:465-480` (`/v1/models`) | Short lease. |
| `sanitize.py:267`, `sanitize.py:324-336` | Short lease for security-model calls. |
| `detectors.py:209` `seed_entities()` | Adds `known_secrets()` from every key source: the management key, the ACTIVE key, and DRAINING keys. |
| `app.py:501` `scrub()` | Same value set. |
| `app.py:115-125` lifespan | Starts and stops the rotation task next to the retention loop. Startup cleanup and the first mint happen **before** the app accepts traffic. |
| `run_gateway.py` | Refuses `workers > 1` when enabled. Opens the custody backend **before** uvicorn starts: prompts for the passphrase in passphrase mode, or pairs with the device in device mode. |

**Q: What config is added?**
Per provider, inside `ProviderConfig` (`extra="forbid"`, so the model must be extended):

```json
{
  "name": "openrouter",
  "base_url": "https://openrouter.ai/api",
  "format": "openai",
  "key_enigma": {
    "enabled": true,
    "kind": "openrouter",
    "instance_id": "3f9a1c07",
    "workspace_id": "0df9e665-d932-5740-b2c7-b52af166bc11",
    "interval_seconds": 900,
    "jitter": 0.2,
    "drain_cap_seconds": null,
    "per_key_limit_usd": 2.0,
    "failure_policy": "closed",
    "delete_unknown": false,
    "custody": {
      "mode": "device",
      "vault_path": null,
      "serial_port": "COM5",
      "device_id": "esp32-a1b2c3d4",
      "pairing_file": null
    }
  }
}
```

Validation:
- `interval_seconds >= 300` and `0 <= jitter <= 0.5`.
- `workspace_id` is **required** and must be a UUID.
- `custody.mode` is `"passphrase"` or `"device"`. There is **no default**: the user has to choose.
- `passphrase` mode requires `vault_path`; if it is `null`, `~/.masqai/openrouter.vault` is used.
- `device` mode requires `serial_port` and `device_id`. `pairing_file` defaults to `~/.masqai/device-<id>.pair`
  (§13.4).
- `drain_cap_seconds: null` means "derive from the upstream timeout".
- `kind` must be `openrouter` in v1; other providers come later.
- When Key Enigma is enabled, `api_key_env` is optional. If it is set, it is used only for the **bootstrap fallback**
  below.
- In device mode, `per_key_limit_usd` and the expiry derived from the interval must stay within the device's
  policy. The device reports its policy when paired; a config that exceeds it is rejected at startup with a clear
  message, rather than failing at the first mint.

**Q: Is there a bootstrap fallback?**
Only if `failure_policy` is `open`: when the very first mint fails, the static `api_key_env` key may be used.
Under `closed`, the gateway refuses to start serving and reports the reason. The static key is never "rotated"; we
only stop using it.

**Q: What does the GUI or API show?**
`GET /api/enigma/status` (admin-token protected, like other `/api/*` routes) returns, per provider:
- the active label and its age;
- DRAINING labels with refcounts;
- the last 50 events;
- the measured propagation delays (min, median, max);
- the approximate spend;
- the management key's expiry, if known.
No key values and no full hashes appear.

**Q: How does this feed the website's `/trust` page?**
`GET /api/enigma/export` produces the exact `keys.json` schema (`web/lib/data.ts:127-149`):
- `label`, `createdAt`, `activeUntil` and `revokedAt`, all in seconds since export start;
- `status: "live"`, `provider: "OpenRouter"`.
For keys that are still active, `activeUntil` and `revokedAt` are the *scheduled* times, because the zod schema
requires numbers. An extra `"projected": true` field is allowed, since zod strips unknown keys.
Labels only, per web/README.md: "never put real … keys … there."

---

## 10. Security review

**Q: What does Key Enigma protect against?**
- Keys leaking through logs, `.env` files, CI, screenshots or agent context: such a key is dead within ~30 min and
  can spend at most $`per_key_limit_usd`.
- A gateway crash leaving keys alive: `expires_at` covers it.
- The admin key leaking through prompt content: covered by the detectors and the separate client.

**Q: What does it NOT protect against?**
1. **Use within the window.** A thief can use a key until it dies (README sacrifice #8).
2. **Full compromise of the gateway host:**
   - In **passphrase mode**, the host's RAM holds the management key, so the attacker can mint keys without limit.
     Only the management key's expiry and the account balance limit the damage.
   - In **device mode**, the attacker gets only inference keys within the device's policy. That is at most 1 key per
     5 min, each capped at $2, all inside the budgeted workspace. The attacker also gets whatever the gateway is
     currently proxying.
3. **Physical theft of the ESP32**, unless flash encryption is enabled (§13.7).
4. **A malicious OpenRouter.** The provider sees everything anyway.
5. **Concentration of risk** (README sacrifice #9). The management key is now the crown jewel. Device mode moves it
   off the host, which is the point of having the device.

**Q: Could rotation itself become an attack surface?**
- **A forced rotation storm:** an attacker who can trigger `401`s could make us mint repeatedly. Emergency rotations
  are capped (3 per 10 min), after which `failure_policy` applies.
- **Our cleanup deleting someone else's keys:** we only delete keys with our exact `instance_id` prefix, and only
  keys we created unless `delete_unknown` is set.
- **SSRF / path injection through `hash`:** hashes are checked against `^[0-9a-f]{64}$` before being put in a URL.

**Q: Are generated values random enough?**
`instance_id`, jitter and every other locally generated value come from `secrets`, which uses the OS CSPRNG
(README: "come from the OS's cryptographically secure random generator"). The key values themselves are created by
OpenRouter.

---

## 11. Testing and measurement

**Q: How do we test without a real account?**
We extend `tests/helpers.py` with a **fake OpenRouter**: a `MockTransport` handler that implements
`POST/GET/PATCH/DELETE /api/v1/keys`, `GET /api/v1/key` and inference endpoints, validates Bearer keys, and simulates
configurable propagation delays and failures. Keys in fixtures contain `FAKE`, so that `scripts/scan_repo.py` passes.

Tests (`tests/test_enigma.py`):
1. A new key is validated before it becomes active, and a key that fails validation is discarded.
2. A stream that started on key N finishes after the swap to N+1 (using `_Chunked`), and N is deleted only afterwards.
3. Concurrent requests during a swap each use exactly one valid key.
4. The drain cap forces revocation of a key whose stream hangs.
5. A `401` on the active key causes an emergency rotation plus one retry when no bytes were sent, and no retry
   after bytes were sent.
6. A `402 openrouter_key_limit` causes an early rotation. `openrouter_credits` does not.
7. A failing `DELETE` is followed by `PATCH disabled`, and then the key is reported as `revoke_failed`.
8. Startup cleanup deletes only `masqai-enigma-<our id>-*`.
9. Under `failure_policy` `closed`, the gateway returns `503 masqai_key_unavailable` once the successor is missing.
   Under `open`, the old key is used until `expires_at`.
10. The management key and active keys are masked if they appear in request content, `scrub()` and `/api/config`.
11. `expires_at` has seconds precision and matches the formula in §5.
12. With `enabled: false`, behavior is byte-for-byte the same as today (`EnvKeySource`).

Custody tests (`tests/test_custody.py`):

13. A sealed vault round-trips. A wrong passphrase fails. Flipping any header byte (`m_kib`, salt, nonce) or any
    ciphertext byte fails. The CLI never prints the key.
14. Startup without a TTY in passphrase mode refuses to start.
15. Device firmware logic runs under CPython. `policy.py`, `proto.py` and `journal.py` are pure Python with no
    MicroPython imports; hardware access sits behind a thin adapter. The tests check that:
    - mints that break policy are refused: limit above the cap, expiry above the cap, wrong workspace, mint rate
      exceeded, too many live keys;
    - revoking a hash that is not in the journal is refused;
    - frames with a bad MAC or a replayed counter are rejected;
    - no command returns the management key or `k_mac`;
    - before `UNLOCK`, every key operation returns `LOCKED`.
16. `DeviceBackend` against a fake serial device: timeouts, a device reboot mid-command, and reconnection.

**Q: How do we fill in the (unverified) facts?**
With `eval/enigma_probe.py`, a manual script that is never run in CI. It uses a real management key and a $0.10
per-key limit, and measures:
- the creation propagation delay;
- the revocation propagation delay, over 20 samples;
- the management endpoint behavior under 1 mint per 10 s for 5 min (stopping at the first `429`);
- whether `PATCH expires_at` is accepted.
Results go into a new "OpenRouter facts" table in this document and update the defaults in §5.

---

## 12. Build order

1. `KeySource` refactor with `EnvKeySource` only. No behavior change; all existing tests stay green. **Done
   2026-10-18:**
   - Code: `masqai/enigma.py` (`KeyLease`, `KeySource`, `EnvKeySource`, `KeyRing`).
   - Tests: `tests/test_enigma.py`. A mutation check confirmed that the stream test fails if a lease is released
     early.
   - Every key read goes through `KeyRing.lease()`; `resolved_key()` is called only by `EnvKeySource`.
2. The `ManagementBackend` protocol, the `OpenRouterKeys` client, a fake OpenRouter in tests, and a fake backend
   for tests. **Done 2026-10-18:**
   - Code: `masqai/custody/__init__.py` (protocol, errors, `load_backend`) and `masqai/custody/openrouter.py`
     (`OpenRouterKeys`, `probe_key`, `DirectBackend`).
   - `DirectBackend` is the host-side backend: passphrase mode (step 6) will be "unseal, then `DirectBackend`".
   - Interface change from §3: `mint(suffix=...)` replaces `mint(label=...)`. The backend builds
     `masqai-enigma-<instance_id>-<suffix>` itself, so a caller cannot mint keys outside the install's prefix, which
     is the same rule the device firmware enforces. `revoke` returns `deleted`, `disabled` or `already_gone`.
   - After each mint, the expiry, limit and workspace that OpenRouter reports are compared with what was requested.
     A key that does not match is revoked immediately and never used.
   - Tests: `tests/test_custody.py`, 32 tests. A mutation check (10 weakened guards, one at a time) confirmed each one
     is caught. The fakes `FakeOpenRouter` and `FakeBackend` are in `tests/helpers.py`.
3. `EnigmaKeySource` state machine, leases and drain. **Done 2026-10-18:**
   - Code: `EnigmaKeySource` and `RotationPolicy` in `masqai/enigma.py`. `KeyRing.start()`/`stop()` run in the app
     lifespan, so the first key is minted and validated **before** the gateway accepts traffic, and every key that
     may still work is revoked at shutdown. `KeyUnavailable` becomes `503 masqai_key_unavailable` on the proxy
     and `/v1/models`, and a fail-closed `SanitizationError` for security-model calls.
   - **Refinement of §4, the swap:** the successor waits as `STANDBY`. The rotation task normally swaps at the
     deadline, but `lease()` also swaps, or refuses, as soon as the deadline has passed. So a key never takes a lease
     after its interval, even if the task is late or has crashed. Both paths use one locked function with no
     `await`, so they cannot both swap.
   - **Refinement of §5:** a key's interval is also capped at `expires_at − drain_cap − safety_margin`. If
     OpenRouter grants a shorter expiry than requested, the key simply rotates sooner, and no stream can outlive it.
   - `known_secrets()` covers active, standby, draining, and revoked-but-not-yet-confirmed-dead keys. A key leaves
     the set when a probe returns 401, or at `expires_at`.
   - Names are `masqai-enigma-<instance>-<run>-<seq>`, with a random 4-hex `run` per start, so names never repeat
     across restarts. The label stays `enigma-<seq>`.
   - The `open` failure policy, the emergency rotation on 401/402, and startup cleanup are step 4.
   - Tests: `tests/test_rotation.py`, 29 tests, using a fake clock, so time-dependent behavior runs in milliseconds.
     They cover a stream that started on key N, survives the swap, and has N revoked only after it ends;
     concurrent leases from 4 threads during swaps; and the drain cap. 20 repeated runs had no flakes. A mutation
     check of 14 weakened guards had every one caught.
4. Failure policy, emergency rotation and startup cleanup. **Done 2026-10-18:**
   - `failure_policy: "open"`: past its interval, with no successor ready, the key keeps serving, but only until
     `expires_at − drain_cap − safety_margin`; then the policy acts as `closed`. A key that was rejected never
     overstays. The rotation task keeps looking for a successor until that hard deadline and swaps as soon as one
     validates.
   - **Emergency rotation:** `rejection_reason()` maps `401` → `revoked_externally` and `402`/`403` with
     `limit_source: openrouter_key_limit` → `key_limit`. Everything else passes through unchanged (credits,
     in-flight budget, guardrails, workspace budget).
     - The key is retired at once and the rotation task wakes to mint a replacement.
     - A `revoked_externally` key is revoked **without draining**, because it may have leaked. A `key_limit` key
       drains normally.
     - Emergencies are capped at 3 per 10 min. Past the cap, the rejected key is still retired, but the gateway
       stays closed until the window passes, rather than minting in a loop.
   - **One retry:** the proxy, streaming or not, sees the upstream status before any byte reaches the client. On a
     key rejection with a fresh key ready, it retries exactly once. With no key ready, the original error is
     returned.
   - **Startup cleanup:** `backend.cleanup()` runs **before** the first mint, so it cannot touch this run's keys.
     A refused management key fails startup. Any other cleanup error is logged, and startup continues, since
     leftovers die at `expires_at`.
   - Tests: `tests/test_enigma_policy.py`.
5. Detector, scrub and status API wiring. **Done 2026-10-18:**
   - `seed_entities(..., secrets=keyring.known_secrets())`: our own keys are masked **regardless of `protect`**,
     like custom values. They win over the `openrouter_key` rule's span and are added to a session only where they
     appear, so they don't fill the mapping table shown in the GUI.
   - Upstream error text and security-model errors are scrubbed with the same values (`<OR_KEY_enigma>`) before
     logging.
   - `GET /api/enigma/status` is admin-token protected and returns, per provider: the active label, keys (label,
     8-char hash prefix, state, refcount, expiry), approximate spend, propagation delays (count/min/median/max),
     the cleanup count and the last 50 events. It contains no key values and no full hashes.
   - Mutation check for steps 4–5: 14 weakened guards, all caught. The step 3 mutation check was re-run after the
     loop changes and still catches all 14.
6. **Passphrase mode:** the vault, the CLI, `PassphraseBackend`, and the startup prompt. **Done 2026-10-18:**
   - Code:
     - `masqai/custody/vault.py`: the format, `seal`/`unseal`, atomic owner-only writes, and the CLI
       `python -m masqai.vault seal|verify|repass|destroy`.
     - `masqai/custody/passphrase.py`: `PassphraseBackend`, which is `DirectBackend` plus the management key as an
       `ADMIN_KEY` secret, wiped on close.
     - `KeyEnigmaConfig`/`CustodyConfig` in `masqai/config.py`; `build_keyring`/`policy_for` in `masqai/enigma.py`.
     - `run_gateway.py` opens the backends before uvicorn.
   - **Refinements of §3.1:**
     - The header also carries `provider` and the management key's stated expiry. Both are authenticated.
     - The Argon2 cost must lie between 64 MiB and 1 GiB, and the field set is exact; both are checked before any
       KDF work.
     - Passphrases are NFC-normalized.
     - `seal` reads the expiry from `GET /api/v1/key` (the OpenAPI example shows `expires_at` there) and asks only
       if it is missing.
   - **Startup order:** check the backend (management key, workspace, budget), then clean up, then mint the first
     key. If the backend is not ready, nothing else runs.
   - **Expiry warnings** at T-7d and T-1d, each once, as a log line and a status event.
   - **Config:** `key_enigma` is validated per §9, but `delete_unknown` is left out until the intruder check exists.
     - The block can't be edited at runtime, since the backend was opened for it. The base URL must be
       `https://openrouter.ai`.
     - A rotating provider never falls back to its env key: `create_app` refuses one without a rotating source.
     - **The §9 bootstrap fallback is not built.** Even under `open`, a failed first mint fails startup instead of
       using `api_key_env`. That fallback would bring back the static key Key Enigma exists to remove (the more
       secure option, DECISIONS.md).
   - Measured on this laptop: one Argon2id derivation at the default cost takes about 0.15 s, so 3 wrong attempts
     cost under 1 s. That is fast enough for startup and still memory-hard for an offline guesser (256 MiB per
     guess).
   - Tests: `tests/test_vault.py`, 52 tests (1 POSIX-only, skipped on Windows). A mutation check (30 weakened
     guards) had every one caught. The step 2–5 mutation checks still catch all of theirs.
7. **Device mode, firmware logic:** `policy.py`, `proto.py` and `journal.py`, tested under CPython.
8. **Device mode, hardware side:** the adapter layer on the ESP32 (Wi-Fi, TLS, NVS, the clock via NTP) and the
   `enroll` CLI. Run a bench test on the real board.
9. The probe script against the real API, then tune the defaults.
10. Export to `keys.json`, then switch `/trust` to `status: "live"`.

Steps 1–5 do not depend on the mode, so steps 6 and 7–8 can run in parallel.

Rule from PLAN.md: start only with the owner's agreement. Record each choice made here in DECISIONS.md.

---

## 13. The ESP32 key-provider device

### 13.1 Goal and threat model

**Q: What does the device protect against, exactly?**
The goal is: **a fully compromised gateway host must not be able to obtain the management key, and must not be able
to obtain inference keys beyond a fixed policy.** "Fully compromised" means the attacker has root or admin on the
host and can read its RAM, files and serial ports.

| Attacker | Gets | Does not get |
|---|---|---|
| Compromised host | The pairing file; inference keys within the policy (§13.5); whatever the gateway is proxying | The management key; the ciphertext in the device's flash; any way to change the policy |
| Anyone who taps the UART wires | Authenticated frames, with inference keys encrypted inside them | Usable keys, or the ability to forge commands |
| Someone who steals the device | The encrypted management key from flash | The unlock secret, which is only on the host. **They need both the device and the host.** |
| Someone who steals the device **and** compromises the host | Everything | — |

### 13.2 Physical wiring: the critical rule

**Q: Why not just plug the ESP32's USB port into the host?**
Because that would hand the host two ways to read the device's memory. This was the main hidden risk in the design:
- **The MicroPython REPL is on the USB serial port.** The host can send Ctrl-C, stop the firmware and read variables,
  or open the files in flash.
- **Most dev boards have an auto-reset circuit** that uses the DTR/RTS lines. With it, the host can reboot the chip
  into the ROM bootloader and dump the entire flash with `esptool read_flash`. On a stock ESP32 nothing prevents this,
  unless one-time eFuses are burned (§13.7).

**So the device talks to the host over a separate 3-wire UART, and its USB port carries power only:**

```
 Gateway host ──USB── [USB-TTL adapter, 3.3 V] ──TX/RX/GND only──> ESP32 UART2 (GPIO16 RX, GPIO17 TX)
 Wall charger or power bank ──USB (power only)──> ESP32 USB port         (no data path to the host)
```

- The adapter's DTR/RTS lines are **not connected**, so the host cannot reset the board or enter the bootloader.
- UART2 runs only our protocol. The REPL stays on UART0/USB, which is not connected to the host.
- To flash firmware or enroll, a person plugs the board's USB into a trusted computer. That is a physical act, and
  it is the intended path for administration.
- If the board's USB *is* connected to the gateway host, the guarantees in §13.1 **do not hold**. The firmware
  can't detect that, so this rule appears in setup docs, in the `enroll` CLI output, and on `/api/enigma/status` as a
  checklist item.

### 13.3 What the device stores

| Item | Where | Protection |
|---|---|---|
| Management key | Flash file `/enigma/mk.bin` | AES-256-CTR + HMAC-SHA256 (encrypt-then-MAC). The wrapping key is `HKDF(unlock_secret)`. |
| `unlock_secret` (32 B) | **Host** pairing file only. On the device: only in RAM while unlocked. | Generated by the device's hardware RNG at enrollment and given to the host once. |
| `k_mac` (32 B) | Device flash and host pairing file | Authenticates frames (§13.4) |
| Policy | Flash `/enigma/policy.json` + HMAC | Changeable only in an enrollment window (§13.6) |
| Wi-Fi SSID/password | Flash | Plaintext. Wi-Fi credentials are lower value. |
| CA roots for openrouter.ai | Flash `/enigma/ca.der` | Public data; replaced only in an enrollment window |
| Journal | Flash `/enigma/journal.jsonl` | `{hash, name, expires_at, state}`. A hash is not usable as a key. |

- A random 256-bit `unlock_secret` needs no slow key derivation. Brute-forcing it is not feasible, so a thief with
  the flash dump but without the host's file gets nothing.
- MicroPython's `cryptolib` provides AES. HMAC is built from `hashlib.sha256`, because MicroPython has no `hmac`
  module. Randomness comes from `os.urandom`, the ESP32's hardware RNG, which is a true RNG while the radio is on.
- The host's pairing file is `~/.masqai/device-<id>.pair` with owner-only permissions.
  **Optionally** it is wrapped with the passphrase vault from §3.1, which turns three factors into one requirement:
  the device, the file and the passphrase.

### 13.4 Host ↔ device protocol

**Q: What does the wire format look like?**
- Newline-delimited JSON over UART2 at 115200 baud. Lines are at most 2 KiB. Binary fields are base64.
- Every request is `{"n":<counter>,"op":"...","a":{...},"m":"<mac>"}`.
  - `m` is `HMAC(k_sess, n ‖ op ‖ canonical(a))`.
  - `n` must strictly increase; replays and reordering are rejected.
- Responses carry the same counter and a MAC.
- `k_sess = HKDF(k_mac, nonce_host ‖ nonce_dev)`, set up in `HELLO`. A new session starts at every reconnect.

| Op | Allowed when | Does |
|---|---|---|
| `HELLO` | always | Exchanges nonces. Returns the device ID, firmware version, state (`UNPROVISIONED` / `LOCKED` / `UNLOCKED` / `ENROLL`), the policy, and the management key's expiry. |
| `UNLOCK` | `LOCKED` | Takes `unlock_secret`, verifies it by decrypting `mk.bin`, and keeps the management key in RAM only. Then: boot checks (§13.6) and journal cleanup. |
| `MINT` | `UNLOCKED` | Takes `seq`, `ttl_s` and `limit_usd`; checks the policy; calls `POST /api/v1/keys`. Returns the key **encrypted under `k_sess`**, plus `hash` and `expires_at`. |
| `REVOKE` | `UNLOCKED` | Takes a `hash`, which must be in the journal. Sends `DELETE`, falling back to `PATCH disabled`. Returns the result. |
| `USAGE` | `UNLOCKED` | Takes a `hash` from the journal and returns `usage`. |
| `CLEANUP` | `UNLOCKED` | Revokes every journal entry that is not `dead`. |
| `STATUS` | always | Returns policy, journal counts, Wi-Fi state, the last error and the rate-limit buckets. |
| `LOCK` | `UNLOCKED` | Wipes the RAM copy of the management key. |
| `ENROLL_*` | `ENROLL` only | §13.6 |

There is **no operation that returns `mk`, `k_mac`, `unlock_secret`, the Wi-Fi password, or any file.**
The firmware has no "read file", "eval" or "update firmware" command. Its whole surface is the list above.

**Q: Why authenticate frames if the host is the only thing on the wire?**
- The MAC stops any other machine plugged into the UART from driving the device.
- Encrypting keys in transit keeps them away from a passive logic analyzer.
- Neither stops a compromised host, which holds `k_mac`. Against that attacker, the protection is the policy (§13.5).

### 13.5 Policy enforced in firmware

These are the defaults, set at enrollment. The host cannot change them.

| Rule | Default | Why |
|---|---|---|
| `workspace_id` | fixed at enrollment | Keys can only exist in the budgeted workspace. |
| `name_prefix` | `masqai-enigma-<instance_id>-` | The device builds the name itself; the host sends only `seq`. |
| `max_limit_usd` | 2.00 | Caps each key. |
| `max_ttl_s` | 1900 | About 31.7 min; matches §5. |
| `min_mint_gap_s` | 240 | Normal rotation is at least 300 s minus jitter. |
| Emergency bucket | 3 mints per 10 min | For the `401` and limit paths in §8. |
| `max_mints_per_day` | 120 | Bounds the worst case. |
| `max_live_keys` | 4 | Active plus draining keys, with some slack. |
| Revoke scope | journal hashes only | A compromised host cannot use the device to delete your other keys. |

**Worst case for a compromised host:**
`min(workspace budget, 120 mints/day × $2) = min(budget, $240/day)`. Pick a workspace budget well below that, such
as $20 per day. Because the device enforces `max_live_keys`, the attacker can't stockpile keys either.

**Q: Who decides `expires_at`, the host or the device?**
The device. It computes `expires_at = server_time + min(ttl_s, max_ttl_s)`, where `server_time` is the **`Date`
header of the device's latest HTTPS response from OpenRouter**. That header is authenticated by TLS, so neither the
host nor a spoofed NTP server can stretch a key's life.
NTP (`ntptime`) is used only to set the clock roughly enough for TLS certificate validity checks. If NTP and the
`Date` header differ by more than 5 min, the device refuses to mint and reports `CLOCK_SKEW`.

### 13.6 Enrollment, boot and memory

**Q: How is the device enrolled?**
Enrollment requires **a person's physical presence**:
1. Hold the **BOOT button (GPIO0) for 3 s** after power-on. The LED blinks fast, and a 120 s enrollment window opens
   on UART2.
2. On a trusted host, run `python -m masqai.device enroll --port COMx`. It prompts with `getpass` for:
   - the management key and its expiry date;
   - the Wi-Fi SSID and password;
   - the `workspace_id`;
   - any policy overrides.
3. The device connects to Wi-Fi and checks the management key and workspace through
   `GET /api/v1/workspaces/{id}` (an inference key gets `403`). It then checks that **the workspace has a budget**
   through `GET .../budgets`, and refuses enrollment if it has none.
4. The device generates `k_mac` and `unlock_secret`, encrypts the management key, and writes its files. It then
   returns `k_mac`, `unlock_secret`, `device_id` and the policy **once**.
5. The host writes the pairing file, optionally sealed with a passphrase. The CLI prints a wiring checklist (§13.2).

Re-enrolling, changing the policy and updating the CA roots all require a new enrollment window. That means a button
press, so it can't be done remotely by a compromised host.
`python -m masqai.device unpair` erases all secrets on the device, also inside an enrollment window.

**Q: What happens when the device boots?**
1. Starts the watchdog (`machine.WDT`, 30 s).
2. Connects to Wi-Fi.
3. Runs NTP.
4. Enters `LOCKED` and waits for `HELLO` and `UNLOCK`.

On `UNLOCK` it:
1. decrypts the management key;
2. checks the workspace again;
3. revokes leftover keys listed in the journal;
4. enters `UNLOCKED`.

A power loss returns it to `LOCKED`, so the management key is never in RAM without the host's secret.

**Q: Which board is the target?** (owner's board, 2026-10-18)

| Fact | Value | Consequence |
|---|---|---|
| Chip/board | Generic ESP32 module (original ESP32, dual-core Xtensa LX6) | Has hardware AES/SHA acceleration for mbedTLS. USB goes through a separate UART bridge chip with DTR/RTS auto-reset, so the §13.2 wiring rule applies. |
| Firmware | MicroPython **v1.27.0** (2025-12-09), language level 3.4.0 | `ssl.SSLContext`, `load_verify_locations(cadata=…)`, `CERT_REQUIRED` and `cryptolib.aes` with `MODE_CTR` (6) are documented for this version. |
| PSRAM | **none** | The §6 "unknown keys with our prefix" check is **off** on the device; journal-based cleanup is used. |
| Free heap at the prompt | **147,232 bytes** | See the memory budget below. |

**Q: Will it fit in ESP32 memory?**
The measured heap is 147 KB. On the ESP32 port, mbedTLS allocates through the ESP-IDF system heap, not MicroPython's
GC heap **(unverified on this board)**. So the TLS handshake (about 40–50 KB) mostly does not come out of the 147 KB,
but it can fail if the system heap is fragmented.

Budget per operation, run one at a time:

| Item | Size |
|---|---|
| Firmware modules (frozen or `.mpy`) | about 20–30 KB GC heap |
| `POST /api/v1/keys` response (create; includes the key) | about 1.5 KB |
| `GET /api/v1/key` or `GET /api/v1/keys/{hash}` | about 1 KB |
| Workspace and budget check at boot | about 2–4 KB |
| `GET /api/v1/keys` (list) | up to about 70 KB per page of 100 keys. **Not used.** |

Rules:
- Responses are read in chunks with a hard cap of 8 KB. A larger body is refused with `RESP_TOO_LARGE` instead of
  crashing the device.
- `gc.collect()` runs before each TLS connection. One connection at a time; it is closed after each call. Keep-alive
  would hold the TLS context in memory between calls.
- Modules are compiled to `.mpy` with `mpy-cross`, to save heap and parse time.
- The bench test logs `gc.mem_free()` and `esp32.idf_heap_info(esp32.HEAP_DATA)` before and after a handshake, and
  over 100 mint/revoke cycles, to catch fragmentation or leaks.

**Q: How does it verify OpenRouter's TLS certificate?** (measured 2026-10-18)
The chain openrouter.ai serves today is:
- leaf `CN=openrouter.ai` (ECDSA), valid until 2027-01-15;
- intermediate `WE1` (Google Trust Services);
- root **GTS Root R4** (ECDSA P-384), valid until 2036-06-22, SHA-256 fingerprint
  `34:9D:FA:40:58:C5:E2:63:12:3B:39:8A:E7:95:57:3C:4E:13:13:C8:3F:E6:8F:93:55:6C:D5:E8:03:1B:3C:7D`.

The server also offers **TLS 1.2 with `ECDHE-ECDSA-AES128-GCM-SHA256`**. That matters because the ESP32's mbedTLS
build may not have TLS 1.3.

I tested this with OpenSSL: trusting **only** GTS Root R4 (525 bytes DER) verifies the live chain successfully.
The leaf certificate rotates about every 90 days, so trusting the root (not the leaf) is the right anchor.

Device code:
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(cadata=open("/enigma/ca.der", "rb").read())
sock = ctx.wrap_socket(raw_sock, server_hostname="openrouter.ai")
```
Notes and open checks:
- `CERT_REQUIRED` needs a correct clock (§13.5). NTP runs before the first connection.
- **Single-root risk:** MicroPython documents that `wrap_socket(cadata=…)` takes only one DER certificate, while
  `load_verify_locations(cadata=…)` is documented as "CA certificates". Whether it accepts several concatenated DER
  roots is **(unverified)**.
  - If it does: bundle **GTS Root R4** plus **GTS Root R1** (RSA, also valid until 2036) as a fallback.
  - If not: ship R4 only. If Cloudflare switches CA, the device fails closed with `TLS_VERIFY_FAILED`. Recovery is
    a new enrollment window to update `ca.der`; `enroll` fetches and shows the new root's fingerprint for the user
    to confirm.
- **Bench test 1, hostname checking: PASSED** (run over ESP32-OTA, 2026-10-18). Connecting to openrouter.ai with
  `server_hostname="example.com"` does **not** test this: Cloudflare serves a genuine `example.com` certificate that
  does not chain to R4, so the CA check rejects it first. Instead:
  - A LAN test server with a throwaway CA served the same `good.test` certificate whatever SNI the client sent. The
    kit was verified against CPython's `ssl` first.
  - Results on the board, all four as expected:

    | Requested name + trusted CA | Result |
    |---|---|
    | `good.test` + test CA | connected, `HTTP/1.0 200` |
    | `evil.test` + test CA | refused: `ValueError: The certificate Common Name (CN) does not match with the expected CN` |
    | `good.test` + wrong CA | refused: `ValueError: … not correctly signed by the trusted CA` |
    | the server's IP + test CA | refused: CN mismatch |

  - The server log confirms the board sent each requested name as SNI and aborted the handshake itself.
  - **Conclusion:** `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` with `CERT_REQUIRED` and `server_hostname=` checks both
    the chain and the name on MicroPython v1.27.0 / ESP32. Device mode can rely on it, so no manual name check is
    needed in firmware.
  - The error text mentions only the CN; the test certificate also has a matching SAN. Free heap went from about
    127 KB before to about 90 KB after four handshakes.
- **Bench test 2, CA checking: PASSED** (owner's run, COM6, 2026-10-18).
  - Trusting only R4, openrouter.ai connected and returned `HTTP/1.1 200`.
  - The `example.com` certificate, a real one from a different chain, was rejected.
  - Memory: about 142 KB free before a handshake and 107 KB after the first. The heap stabilizes around 107–109 KB,
    with about 2 KB retained per handshake. Watch this in the 100-cycle soak test.
- **Firmware rule from this run:** on MicroPython v1.27.0 / ESP32, a certificate verification failure is raised as
  **`ValueError`** ("The certificate is not correctly signed by the trusted CA"), **not `OSError`**. The device's
  HTTPS wrapper must catch both and map them to `TLS_VERIFY_FAILED`. If it doesn't, a verification failure crashes
  the command loop instead of failing closed.

### 13.7 Limits we accept

**Q: What if someone steals the board?**
On stock MicroPython, flash is readable by anyone holding the board (BOOT button + USB + `esptool`). The thief gets
the encrypted `mk.bin` but **not** `unlock_secret`, which is only on the host. To use the key they also need the
pairing file. Flash encryption and disabling download mode would close this gap, but both burn **irreversible
eFuses** and need a custom MicroPython build, so they are out of scope.
If the board is stolen: delete the management key on OpenRouter and enroll a new one.

**Q: Why not use BLE or Wi-Fi between the host and the device?**
A wired UART has no pairing UX, no radio attack surface, and a physical connection you can see. Wi-Fi is used only
for the device's own outbound HTTPS to OpenRouter.

**Q: Why not send all inference traffic through the device?**
It would be far too slow and would run out of memory on streams. The security boundary is the *key*, not the
traffic: the device decides which keys exist, and the gateway uses them.

**Q: Is there anything else to know?**
- **Latency:** a mint goes over UART, then TLS from the ESP32 (about 1–3 s), then back. That happens once every
  15 min and ahead of the deadline, so users never notice.
- **Dependencies:** host side adds `pyserial`. Firmware is plain MicroPython with no extra libraries.
- **Testing:** `policy.py`, `proto.py` and `journal.py` are pure Python and run under CPython in CI (§11 #15). The
  Wi-Fi, TLS and file layer is a small adapter that is tested on the real board.
