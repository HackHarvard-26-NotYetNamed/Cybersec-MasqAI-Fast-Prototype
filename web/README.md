# MasqAI public site

The public showcase for MasqAI: a Next.js (App Router) site deployed on Vercel.

**It never touches real traffic.** The gateway is localhost-only by design, so this site has no
backend, no API routes, no proxy, no database and no auth. Every page is prerendered static output
that reads static JSON from `public/`. All of that data is synthetic. Whatever you put in
`public/data/` gets published, so never put real traces, keys or identities there.

| Route | What it shows | Data |
|---|---|---|
| `/` | Tagline, two-way mirror hero, origin story, secret vs. intel, two assets / two threats | none |
| `/demo` | Replay theater: agent vs. untrusted model, decision panel, relinks, hygiene, blocked states, ←/→/space, "Without MasqAI" | `public/data/replays/` |
| `/results` | Stat tiles, one chart per metric, prompt-injection results, methodology, honesty note | `public/data/results.json` |
| `/how-it-works` | Seven-stage pipeline with fail-closed exits, why not just regex, trust model, hardening, trade-offs | none |
| `/trust` | Key Enigma key lifetimes and honeytoken alerts (a design preview while planned) | `public/data/keys.json` |
| `/run-it` | How to start the gateway and use its built-in GUI | `public/media/media.json` |

There is deliberately no live view. The gateway refuses cross-origin browser requests and needs a
per-start admin token. Its own GUI at `http://127.0.0.1:8787` is the live view.

## Run and build

```bash
cd web
npm install
npm run dev        # http://localhost:3000
npm run build      # static build; fails on type errors
npm run lint
```

`predev` and `prebuild` run `scripts/index-replays.mjs`, which rewrites
`public/data/replays/index.json` (an array of `{id, title, file}`) from the replay files in that
folder.

## Deploy to Vercel

Import the repository and set **Root Directory** to `web`. Nothing else is needed: no environment
variables and no build settings.

## Replacing the mock data

Every file is validated with zod in [`lib/data.ts`](lib/data.ts), with field names exactly as the
gateway and the eval harness emit them. A missing or malformed file shows an error card naming the
file and the failing field; the rest of the site keeps working.

To update an existing file, replace it and redeploy (or reload under `npm run dev`). New files,
such as an extra replay, need a rebuild, which also regenerates the replay index.

### Replays: from the gateway's replay export

The gateway exports one session in the replay format, but only when it was started with
`--playground`, because the export contains raw values. The request needs the admin token printed
at startup:

```bash
curl -s -H "x-masqai-token: $MASQAI_ADMIN_TOKEN" \
  "http://127.0.0.1:8787/api/sessions/<session-id>/replay?synthetic=1" \
  > web/public/data/replays/uc2-db-path.json
```

The gateway streams the JSON to the caller and never writes a file itself. Then:

1. Set `id` to the file name (`uc2-db-path`), and fill in `title` and `summary` (the export leaves them empty).
2. Check that every value is synthetic. Playground secrets are fake, but host identifiers (hostname,
   username, home path) come from the real machine; replace them with `alice`, `DESKTOP-7Q2XK9M`
   and so on before committing.
3. Rebuild. `/demo` lists the file automatically.

Notes on the fields:

- `steps[].ops[]`: `op` is `mask | hide | replace | relink | unmask`, and `source · verdict` is one
  of `detector | auto | model` × `applied | vetoed | left_as_is | rejected_invalid`. Every
  combination renders; `model · applied` is emphasized in violet.
- Locating ops in the text: masks by `placeholder` in `sanitized`, replaces by `with`, hides by the
  `…[hidden: …]…` marker, and raw values by `value` in `raw` (at word boundaries, like the
  gateway's auto masks). An op that can't be located is still listed in the decision panel; only
  the inline highlight is skipped.
- `steps[].relinks[].stepsRewritten` are **0-based indexes into `steps`**. From the relink step
  onward, those steps show `toPlaceholder` instead of `fromPlaceholder`, tagged "prompt cache
  broken: accepted for privacy".
- `blocked` is `null` or `{reason, status}`. The five reasons map to the labels in
  `BLOCK_REASONS` in `lib/data.ts`.
- The corner counter is computed. `user` and `tool` steps count as requests (blocked ones don't,
  unless "Without MasqAI" is on). A value counts as exposed only if it still appears verbatim in
  `sanitized`. `relayRequestCount` is shown nowhere but kept for the gateway contract.

### `results.json`: from the eval harness

Produced by the Daytona harness in [`eval/`](../eval/README.md):

```bash
python -m eval.run_eval --config local-security-models --runs 20 --publish   # or the GUI: python -m eval.gui
python -m eval.run_eval --injection --runs 20        # optional: fills `injection`
python -m eval.aggregate eval/out/campaigns/<id>/runs.jsonl   # re-aggregate a campaign (writes its report.md)
```

With several masqai conditions, the site shows the first raw and the first masqai condition; the full
per-condition data stays in `conditions` / `cases[].conditions`.

```json
{
  "placeholder": false,
  "generatedAt": "2026-10-18T03:00:00Z",
  "runsPerCase": 20,
  "securityModel": "qwen2.5:7b (local)",
  "untrustedModel": "via playground relay",
  "agent": "OpenCode",
  "sandbox": "Daytona",
  "cases": [
    { "id": "uc2-db-path", "title": "Production DB path",
      "raw":    { "leakRate": 1.0, "taskSuccess": 0.95, "avgTokens": 5120, "p50LatencyMs": 2100 },
      "masqai": { "leakRate": 0.0, "taskSuccess": 0.90, "avgTokens": 3010, "p50LatencyMs": 2900 } }
  ],
  "injection": [
    { "attack": "return empty operations", "attempts": 20, "succeeded": 7 }
  ]
}
```

- Rates are 0–1. While `"placeholder": true`, `/results` carries a large diagonal
  **PLACEHOLDER: replace with real eval run** watermark.
- The headline tiles are derived:
  - leak rate and task success: means over cases
  - tokens saved: `1 − Σ masqai.avgTokens / Σ raw.avgTokens`
  - latency added: the median of the per-case p50 differences
- `injection` comes from the harness's `tests/injection/` report. Each row is drawn as a success-rate
  bar under "Known open issue. Measured, not yet defended."

### `keys.json`: from the Key Enigma log

```json
{
  "status": "planned",
  "provider": "OpenRouter",
  "keys": [{ "label": "enigma-001", "createdAt": 0, "activeUntil": 300, "revokedAt": 330 }],
  "honeytokens": [{ "label": "canary-7", "plantedAt": 120, "usedAt": 410, "usedBy": "relay (playground)", "verdict": "untrustworthy" }]
}
```

- Times are seconds since the start of the demo.
- The grace period runs from `activeUntil` to `revokedAt`.
- `"usedAt": null` means the canary was never triggered.
- The checked-in file remains `planned` demo data until replaced by a real gateway export. With a running Key Enigma
  gateway, export its public timeline using `python scripts/export_enigma.py --url http://127.0.0.1:8787 --token <admin-token>`.
  The token is the local GUI admin token printed at gateway startup. The exporter validates and writes only labels and
  relative times; it strips hashes and all extra fields. `/trust` displays the live badge when the exported file says
  `status: "live"`. Honeytokens remain planned until that feature is implemented.

### `media/media.json`: GUI recordings for `/run-it`

```json
{ "items": [{ "kind": "video", "src": "/media/gui-context.webm", "alt": "The Context tab replaying UC2", "caption": "optional" }] }
```

Put the files next to `media.json`. Record with synthetic playground data only; the GUI shows raw
values. While `items` is empty, the page shows an empty slot.

## Design notes

- Copy always says **untrusted model** and **security model**.
- Dark by default, with a light theme (the choice is stored in `localStorage`). Mono for context
  text and placeholders, sans for UI, and replay text is at least 15px.
- Colors carry meaning, and every colored mark also has an icon and a text label:

  | Color | Meaning |
  |---|---|
  | red | raw secret / leaked |
  | one color per type (PATH blue, KEY orange, EMAIL lime, HOST cyan, USER pink) | masked |
  | dashed outline | alias (`<$…>`) |
  | dashed amber | intel replaced |
  | muted gray | intel hidden |
  | green | restored locally |
  | violet | found by the security model |

- Chart series colors (orange = raw, blue = MasqAI) were checked for color-vision-deficiency
  separation in both themes.
- Mobile: the split screen becomes Agent / Untrusted model tabs, and the decision panel moves into
  a drawer.
