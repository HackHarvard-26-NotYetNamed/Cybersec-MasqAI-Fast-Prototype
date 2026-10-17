# MasqAI public site

The public showcase for MasqAI: a Next.js (App Router) site deployed on Vercel.

**It never touches real traffic.** The gateway is localhost-only by design, so this site has no
backend, no API routes, no database and no auth. Every page is prerendered static output and reads
static JSON from `public/data/`. All of that data is synthetic, taken from the playground's fake
secrets. Never put real traces, keys or identities in `public/data/`: whatever is in there gets
published.

| Route | What it shows | Data |
|---|---|---|
| `/` | Tagline, two-way mirror hero, origin story, two assets / two threats | none |
| `/demo` | Replay theater: agent view and relay view side by side, ←/→/space, "Without MasqAI" toggle | `public/data/replays/*.json` |
| `/results` | Stat tiles, one chart per metric, methodology, honesty note | `public/data/results.json` |
| `/how-it-works` | Pipeline diagram, trust model, trade-offs | none |
| `/trust` | Key Enigma key lifetimes and honeytoken alerts | `public/data/keys.json` |
| `/live` | Optional: a running local gateway (local dev only) | the gateway itself |

## Run and build

```bash
cd web
npm install
npm run dev        # http://localhost:3000
npm run build      # static build; fails on type errors
npm run lint
```

`predev` and `prebuild` run `scripts/index-replays.mjs`, which regenerates
`public/data/replays/index.json` from the files in that folder.

## Deploy to Vercel

Import the repository and set **Root Directory** to `web`. Nothing else is needed: no environment
variables and no build settings. `NEXT_PUBLIC_LIVE_MODE` defaults to off, and `/live` then shows
an explainer.

## Replacing the mock data

Every file is validated with zod in [`lib/data.ts`](lib/data.ts). A missing or malformed file shows
a friendly error naming the file and the failing field; the rest of the site keeps working. Swapping
a file needs no code change. With `npm run build`, the new file ships on the next deploy. With
`npm start` or `npm run dev`, a reload picks it up.

### `results.json`: from the eval harness

```json
{
  "placeholder": false,
  "generatedAt": "2026-10-18T03:00:00Z",
  "runsPerCase": 20,
  "model": "qwen2.5:7b",
  "agent": "Factory Droid",
  "sandbox": "Daytona",
  "cases": [
    {
      "id": "uc2-db-path",
      "title": "Production DB path",
      "raw":    { "leakRate": 1.0, "taskSuccess": 0.95, "avgTokens": 5120, "p50LatencyMs": 2100 },
      "masqai": { "leakRate": 0.0, "taskSuccess": 0.90, "avgTokens": 3010, "p50LatencyMs": 2900 }
    }
  ]
}
```

- Rates are 0–1. `avgTokens` is per run; `p50LatencyMs` is the per-case median.
- The shipped file has `"placeholder": true`, which puts a **PLACEHOLDER — replace with real eval
  run** watermark on `/results`. Have the harness write `false` (or omit the field).
- The headline tiles are derived. Leak rate and task success are means over cases. Tokens saved is
  `1 − Σ masqai.avgTokens / Σ raw.avgTokens`. Latency added is the median of per-case
  `masqai.p50LatencyMs − raw.p50LatencyMs`.
- Case ids starting with `ucN` are shown as `UCN` on chart axes.

### `replays/*.json`: exported from gateway traces

One file per use case. Drop new files into `public/data/replays/`; the index is rebuilt on the next
`dev` or `build`.

```json
{
  "id": "uc2-db-path",
  "title": "Production DB path",
  "summary": "One or two sentences shown above the panes.",
  "relayRequestCount": 4,
  "steps": [
    {
      "t": 0,
      "role": "user | assistant | tool",
      "raw": "what the agent produced (agent pane)",
      "sanitized": "what was forwarded upstream (relay pane)",
      "entities": [
        { "type": "PATH", "placeholder": "<PATH_b71e04d2>", "value": "C:\\Users\\alice\\...", "op": "mask | partial | collapse", "missed": false }
      ],
      "toolCall": { "name": "bash", "argsSent": "sqlite3 \"<PATH_b71e04d2>\" ...", "argsRestored": "sqlite3 \"C:\\Users\\alice\\...\" ..." },
      "blocked": false,
      "note": "optional narration that replaces the auto-generated caption"
    }
  ]
}
```

How the fields map to what the gateway records:

- **`raw` / `sanitized`**: one session item before and after sanitizing. In `user` and `tool` steps
  the agent sends context upstream. In `assistant` steps the model replies, and `raw` equals
  `sanitized` because chat text is not restored.
- **`entities`**: the session's mapping-table entries that occur in this step. `type` picks the
  chip color: `PATH`, `KEY`, `EMAIL`, `HOST` or `USER` (anything else renders as a neutral chip).
  `op: "partial"` is an alias (`<$…>`). For `op: "collapse"`, `placeholder` is the full
  `…[MASQ_BLOCK: summary]…` marker and `value` is the original block. Set `missed: true` when a
  value reached upstream verbatim; it is shown as leaked and counted as exposed.
- **`toolCall`**: the model's tool call. `argsSent` holds the arguments as the model wrote them
  (with placeholders) and `argsRestored` holds them after local restore.
- **`blocked`**: the gateway failed closed (HTTP 502). The relay pane shows nothing for that step.
- **`relayRequestCount`**: should equal the number of non-blocked `user`/`tool` steps. The corner
  counter is computed from the steps.

Placeholders matching `<TYPE_hex>` and `…[MASQ_BLOCK: …]…` markers are recognized by pattern,
even when they are not listed in `entities`.

There is no exporter yet. Write replays only from **playground runs**, whose secrets are synthetic.
The host identifiers in a playground run (hostname, username, home path) are real. Replace them
with fake values such as `alice` and `DESKTOP-7Q2XK9M` before committing.

### `keys.json`: from the Key Enigma log

```json
{
  "placeholder": false,
  "provider": "OpenRouter",
  "keys": [
    { "label": "enigma-001", "createdAt": 0, "activeUntil": 300, "revokedAt": 330 }
  ],
  "honeytokens": [
    { "label": "canary-7", "plantedAt": 120, "usedAt": 410, "usedBy": "relay (playground)", "verdict": "untrustworthy" }
  ]
}
```

Times are seconds since the start of the demo. The grace period runs from `activeUntil` to
`revokedAt`. A honeytoken with `"usedAt": null` (and `"usedBy": null`) has not been triggered;
one with a number raises the red alert on `/trust`. Key Enigma and honeytokens are planned
features, so the shipped file is simulated and marked `"placeholder": true`.

## Live mode (local only)

```bash
python run_gateway.py                      # repository root, gateway on 127.0.0.1:8787
cd web && NEXT_PUBLIC_LIVE_MODE=true npm run dev
```

Then open http://localhost:3000/live.

The gateway rejects cross-origin browser requests, so the page can't fetch `127.0.0.1:8787`
directly. Instead, in dev with live mode on, `next.config.ts` adds rewrites for exactly three
read-only endpoints: `/gateway/api/{state,security,events}` → `127.0.0.1:8787/api/…`. The gateway
still applies its Host, Origin and Sec-Fetch-Site checks to the proxied requests, and cross-site
requests through the proxy get 403. Production builds never contain these rewrites.

`/api/events` is Server-Sent Events. Live mode turns off response compression, which would
otherwise buffer the stream. The page shows only metadata (trace id, status, stage, endpoint,
timing), never context or error text, so it is safe on a projector. For raw values, use the
gateway's own inspector at http://127.0.0.1:8787.

## Design notes

- Dark by default, with a light theme (the choice is stored in `localStorage`). Mono for context
  text and placeholders, sans for UI. Replay text is at least 15px.
- Colors carry meaning, and every colored element also has an icon or label. Red is a real or
  leaked value. Chip colors mark the masked type. Gray is collapsed. Green is restored locally.
- Chart series colors (orange = raw, blue = MasqAI) avoid the red and green meanings and were
  checked for color-vision-deficiency separation in both themes.
- Under 768px wide, the replay's split screen becomes Agent / Relay tabs.
