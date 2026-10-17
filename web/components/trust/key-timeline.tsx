"use client";

import { Bell, FlaskConical, KeyRound, OctagonX, RefreshCw, Sprout, TriangleAlert } from "lucide-react";
import { KeysSchema, useJson, type Keys } from "@/lib/data";
import { DataError, Loading } from "@/components/site/page-bits";

const fmt = (s: number) => `${Math.floor(s / 60)}:${String(Math.round(s % 60)).padStart(2, "0")}`;

export function KeyTrust() {
  const keys = useJson("/data/keys.json", KeysSchema);
  if (keys.status === "loading") return <Loading label="Loading key log" />;
  if (keys.status === "error") return <DataError url={keys.url} message={keys.message} />;
  return <KeyTrustBody data={keys.data} />;
}

function KeyTrustBody({ data }: { data: Keys }) {
  const alerts = data.honeytokens.filter((h) => h.usedAt !== null);
  return (
    <div className="space-y-6">
      {data.status === "planned" ? (
        <p
          role="note"
          className="flex flex-wrap items-center gap-2 rounded-lg border-2 border-dashed border-foreground/40 bg-card px-4 py-3"
        >
          <span className="rounded-full bg-foreground px-2.5 py-0.5 font-mono text-sm font-bold text-background">Planned</span>
          <FlaskConical aria-hidden className="size-5 shrink-0" />
          <span className="font-medium">
            Design preview. Key Enigma and honeytokens are stretch goals; this timeline is simulated.
          </span>
        </p>
      ) : null}

      {alerts.map((h) => (
        <p
          key={h.label}
          role="alert"
          className="flex items-start gap-3 rounded-lg border border-leak/60 bg-leak/10 p-4 text-lg"
        >
          <TriangleAlert aria-hidden className="mt-1 size-5 shrink-0 text-leak" />
          <span>
            <strong className="font-semibold text-leak">Canary used by {h.usedBy ?? "an unknown endpoint"}</strong>: endpoint
            marked {h.verdict}.{" "}
            <span className="text-muted-foreground">
              ({h.label}, planted at {fmt(h.plantedAt)}, used at {fmt(h.usedAt!)})
            </span>
          </span>
        </p>
      ))}

      <figure className="rounded-xl border bg-card p-4 sm:p-5">
        <figcaption className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <span className="font-semibold">{data.provider} key lifetimes</span>
          <span className="text-sm text-muted-foreground">time since the demo started (m:ss)</span>
        </figcaption>
        <Legend />
        <div className="mt-3 overflow-x-auto" tabIndex={0} aria-label="Key timeline (scrolls sideways on small screens)">
          <Timeline data={data} />
        </div>
      </figure>

      <EventLog data={data} />
    </div>
  );
}

const ROW = 40;
const LEFT = 120;
const WIDTH = 1000;

function Timeline({ data }: { data: Keys }) {
  const end =
    Math.max(
      ...data.keys.map((k) => k.revokedAt),
      ...data.honeytokens.map((h) => Math.max(h.plantedAt, h.usedAt ?? 0)),
      60,
    ) + 60;
  const x = (t: number) => LEFT + (t / end) * (WIDTH - LEFT - 16);
  const rows = data.keys.length + data.honeytokens.length;
  const height = 28 + rows * ROW + 8;
  const step = end > 1200 ? 300 : end > 600 ? 120 : 60;
  const ticks = Array.from({ length: Math.floor(end / step) + 1 }, (_, i) => i * step);

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${height}`}
      className="min-w-[720px] font-mono text-[13px]"
      role="img"
      aria-label="Timeline of upstream key lifetimes and honeytoken events. The same events are listed in the event log below."
    >
      <defs>
        <pattern id="grace-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="6" className="stroke-ent-key" strokeWidth="2.5" />
        </pattern>
      </defs>

      {ticks.map((t) => (
        <g key={t}>
          <line x1={x(t)} x2={x(t)} y1={20} y2={height - 4} className="stroke-border" />
          <text x={x(t)} y={12} textAnchor="middle" className="fill-muted-foreground">
            {fmt(t)}
          </text>
        </g>
      ))}

      {data.keys.map((k, i) => {
        const y = 28 + i * ROW;
        return (
          <g key={k.label}>
            <text x={0} y={y + 18} className="fill-foreground">
              {k.label}
            </text>
            <rect x={x(k.createdAt)} y={y + 6} width={Math.max(2, x(k.activeUntil) - x(k.createdAt))} height={18} rx={4} className="fill-ent-key" />
            {k.revokedAt > k.activeUntil ? (
              <rect
                x={x(k.activeUntil)}
                y={y + 6}
                width={x(k.revokedAt) - x(k.activeUntil)}
                height={18}
                fill="url(#grace-hatch)"
                className="stroke-ent-key"
                strokeWidth={1}
              />
            ) : null}
            <g className="stroke-muted-foreground" strokeWidth={2}>
              <line x1={x(k.revokedAt) + 3} x2={x(k.revokedAt) + 11} y1={y + 11} y2={y + 19} />
              <line x1={x(k.revokedAt) + 11} x2={x(k.revokedAt) + 3} y1={y + 11} y2={y + 19} />
            </g>
          </g>
        );
      })}

      {data.honeytokens.map((h, i) => {
        const y = 28 + (data.keys.length + i) * ROW;
        const stop = h.usedAt ?? end;
        return (
          <g key={h.label}>
            <text x={0} y={y + 18} className="fill-foreground">
              {h.label}
            </text>
            <line x1={x(h.plantedAt)} x2={x(stop)} y1={y + 15} y2={y + 15} strokeDasharray="4 4" className="stroke-muted-foreground" strokeWidth={2} />
            <path d={`M ${x(h.plantedAt)} ${y + 8} l 7 7 l -7 7 l -7 -7 z`} className="fill-foreground" />
            {h.usedAt !== null ? (
              <g>
                <line x1={x(h.usedAt)} x2={x(h.usedAt)} y1={22} y2={y + 15} className="stroke-leak" strokeWidth={2} />
                <circle cx={x(h.usedAt)} cy={y + 15} r={8} className="fill-leak" />
                <text x={x(h.usedAt) + 14} y={y + 19} className="fill-leak font-semibold">
                  used by {h.usedBy ?? "unknown"} → {h.verdict}
                </text>
              </g>
            ) : (
              <text x={x(stop) - 4} y={y + 10} textAnchor="end" className="fill-muted-foreground">
                {h.verdict}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function Legend() {
  return (
    <ul aria-label="Legend" className="flex flex-wrap gap-x-5 gap-y-2 text-sm">
      <li className="flex items-center gap-2">
        <span aria-hidden className="inline-block h-3 w-6 rounded-sm bg-ent-key" /> Active
      </li>
      <li className="flex items-center gap-2">
        <svg aria-hidden width="24" height="12">
          <rect width="24" height="12" fill="url(#grace-hatch)" className="stroke-ent-key" />
        </svg>
        Grace period (still accepted, no longer issued)
      </li>
      <li className="flex items-center gap-2 text-muted-foreground">
        <OctagonX aria-hidden className="size-4" /> Revoked (×)
      </li>
      <li className="flex items-center gap-2">
        <span aria-hidden className="inline-block size-3 rotate-45 bg-foreground" /> Canary planted
      </li>
      <li className="flex items-center gap-2 text-leak">
        <span aria-hidden className="inline-block size-3 rounded-full bg-leak" /> Canary used: alert
      </li>
    </ul>
  );
}

type Event = { t: number; icon: typeof KeyRound; text: string; alert?: boolean };

function EventLog({ data }: { data: Keys }) {
  const events: Event[] = [];
  for (const k of data.keys) {
    events.push({ t: k.createdAt, icon: KeyRound, text: `${k.label} issued` });
    events.push({ t: k.activeUntil, icon: RefreshCw, text: `${k.label} rotated out (grace until ${fmt(k.revokedAt)})` });
    events.push({ t: k.revokedAt, icon: OctagonX, text: `${k.label} revoked` });
  }
  for (const h of data.honeytokens) {
    events.push({ t: h.plantedAt, icon: Sprout, text: `${h.label} planted in outgoing context` });
    if (h.usedAt !== null)
      events.push({
        t: h.usedAt,
        icon: Bell,
        text: `${h.label} used from ${h.usedBy ?? "an unknown endpoint"}: endpoint marked ${h.verdict}`,
        alert: true,
      });
  }
  events.sort((a, b) => a.t - b.t || Number(b.alert ?? false) - Number(a.alert ?? false));
  return (
    <details className="rounded-lg border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">Event log ({events.length} events)</summary>
      <ol className="space-y-1 px-4 pb-4">
        {events.map((e, i) => (
          <li key={i} className={`flex items-center gap-3 ${e.alert ? "font-medium text-leak" : ""}`}>
            <span className="w-12 shrink-0 text-right font-mono tabular-nums text-muted-foreground">{fmt(e.t)}</span>
            <e.icon aria-hidden className="size-4 shrink-0" />
            {e.text}
          </li>
        ))}
      </ol>
    </details>
  );
}
