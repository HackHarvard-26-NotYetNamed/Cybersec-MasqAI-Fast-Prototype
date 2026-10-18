"use client";

import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Bug, Clock, Coins, FlaskConical, Info, ShieldAlert, Target } from "lucide-react";
import type { ReactNode } from "react";
import { ResultsSchema, useJson, type Metrics, type Results } from "@/lib/data";
import { useThemeColors } from "@/lib/use-theme-colors";
import { DataError, Loading } from "@/components/site/page-bits";

const WATERMARK = "PLACEHOLDER: replace with real eval run";

const pct = (v: number) => `${Math.round(v * 100)}%`;
const ms = (v: number) => `${Math.round(v).toLocaleString("en-US")} ms`;
const tokens = (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${Math.round(v)}`);
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;
const median = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const ucLabel = (id: string) => id.match(/^uc(\d+)/i)?.[0].toUpperCase() ?? id;

type MetricKey = keyof Metrics;
type Metric = {
  key: MetricKey;
  title: string;
  better: string;
  format: (v: number) => string;
  axis?: (v: number) => string;
  domain?: [number, number];
  // Direct-label the MasqAI bars: on leak rate a 0% bar is otherwise invisible.
  labelMasq?: boolean;
};
const METRICS: Metric[] = [
  { key: "leakRate", title: "Leak rate", better: "lower is better", format: pct, domain: [0, 1], labelMasq: true },
  { key: "taskSuccess", title: "Task success", better: "higher is better", format: pct, domain: [0, 1] },
  { key: "avgTokens", title: "Average tokens per run", better: "lower is better", format: tokens },
  { key: "p50LatencyMs", title: "Median latency (p50)", better: "lower is better", format: ms, axis: (v) => `${(v / 1000).toFixed(1)} s` },
];

export function ResultsView() {
  const results = useJson("/data/results.json", ResultsSchema);
  if (results.status === "loading") return <Loading label="Loading evaluation results" />;
  if (results.status === "error") return <DataError url={results.url} message={results.message} />;
  return <ResultsBody data={results.data} />;
}

function ResultsBody({ data }: { data: Results }) {
  const { cases } = data;
  const leakRaw = mean(cases.map((c) => c.raw.leakRate));
  const leakMasq = mean(cases.map((c) => c.masqai.leakRate));
  const okRaw = mean(cases.map((c) => c.raw.taskSuccess));
  const okMasq = mean(cases.map((c) => c.masqai.taskSuccess));
  const sum = (k: MetricKey, side: "raw" | "masqai") => cases.reduce((a, c) => a + c[side][k], 0);
  const saved = 1 - sum("avgTokens", "masqai") / sum("avgTokens", "raw");
  const latency = median(cases.map((c) => c.masqai.p50LatencyMs - c.raw.p50LatencyMs));

  return (
    <div className="relative space-y-8">
      {data.placeholder ? <Watermark /> : null}

      <section aria-labelledby="headline">
        <h2 id="headline" className="sr-only">
          Headline numbers
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tile icon={<ShieldAlert aria-hidden className="size-4" />} label="Leak rate" detail="mean over use cases">
            <Compare raw={pct(leakRaw)} masq={pct(leakMasq)} />
          </Tile>
          <Tile icon={<Target aria-hidden className="size-4" />} label="Task success" detail="mean over use cases">
            <Compare raw={pct(okRaw)} masq={pct(okMasq)} />
          </Tile>
          <Tile icon={<Coins aria-hidden className="size-4" />} label="Tokens saved" detail="total tokens, MasqAI vs raw">
            <span className="text-4xl font-semibold tabular-nums">{pct(saved)}</span>
          </Tile>
          <Tile icon={<Clock aria-hidden className="size-4" />} label="Latency added" detail="median of per-case p50 deltas">
            <span className="text-4xl font-semibold tabular-nums">
              {latency >= 0 ? "+" : "−"}
              {ms(Math.abs(latency))}
            </span>
          </Tile>
        </div>
      </section>

      <section aria-labelledby="per-case" className="space-y-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 id="per-case" className="text-xl font-semibold">
              Per use case
            </h2>
          </div>
          <SeriesLegend />
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {METRICS.map((m) => (
            <MetricChart key={m.key} metric={m} data={data} />
          ))}
        </div>
        <ResultsTable data={data} />
      </section>

      {data.injection.length ? <Injection attacks={data.injection} /> : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <section aria-labelledby="method" className="rounded-lg border bg-card p-5">
          <h2 id="method" className="flex items-center gap-2 text-lg font-semibold">
            <FlaskConical aria-hidden className="size-5" />
            Methodology
          </h2>
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2">
            <Row k="Runs per case" v={String(data.runsPerCase)} />
            <Row k="Security model" v={data.securityModel} />
            <Row k="Untrusted model" v={data.untrustedModel} />
            <Row k="Agent" v={data.agent} />
            <Row k="Sandbox" v={data.sandbox} />
            <Row k="Date" v={formatDate(data.generatedAt)} />
            <Row k="Use cases" v={String(cases.length)} />
          </dl>
        </section>
        <section aria-labelledby="honesty" className="rounded-lg border-2 border-foreground/30 bg-card p-5">
          <h2 id="honesty" className="flex items-center gap-2 text-lg font-semibold">
            <Info aria-hidden className="size-5" />
            Honesty note
          </h2>
          <p className="mt-3 text-lg text-pretty">
            Lower exposure, not zero: a 7B local model misses things.
          </p>
        </section>
      </div>
    </div>
  );
}

function formatDate(iso: string) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }) + " UTC";
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="font-mono">{v}</dd>
    </>
  );
}

function Watermark() {
  return (
    <>
      <p
        role="note"
        className="flex items-center gap-2 rounded-lg border-2 border-dashed border-foreground/40 bg-card px-4 py-3 font-mono font-semibold"
      >
        <FlaskConical aria-hidden className="size-5 shrink-0" />
        {WATERMARK}. These numbers are mock values, not measurements.
      </p>
      {/* One large diagonal mark across the viewport, behind nothing interactive. */}
      <div aria-hidden className="pointer-events-none fixed inset-0 z-30 flex items-center justify-center overflow-hidden select-none">
        {/* Drawn with a pseudo-element: purely visual, the banner above carries the same text. */}
        <span
          data-text={WATERMARK}
          className="-rotate-[28deg] font-mono text-[clamp(2.25rem,7vw,6.5rem)] font-black tracking-wider whitespace-nowrap text-foreground opacity-[0.07] before:content-[attr(data-text)]"
        />
      </div>
    </>
  );
}

function Injection({ attacks }: { attacks: Results["injection"] }) {
  return (
    <section aria-labelledby="injection" className="rounded-lg border border-leak/50 bg-card p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="injection" className="flex items-center gap-2 text-xl font-semibold">
          <Bug aria-hidden className="size-5 text-leak" />
          Prompt injection against the security model
        </h2>
        <p className="rounded-full border border-leak/60 px-3 py-0.5 text-sm font-medium text-leak">
          Known open issue. Measured, not yet defended.
        </p>
      </div>
      <p className="mt-2 max-w-3xl text-muted-foreground">
        Planted text that tries to talk the security model out of its job. Bar = attacks that worked.
      </p>
      <ul className="mt-4 space-y-3">
        {attacks.map((a) => {
          const rate = a.succeeded / a.attempts;
          return (
            <li key={a.attack} className="grid gap-1 sm:grid-cols-[14rem_1fr_12rem] sm:items-center sm:gap-4">
              <span className="font-medium">{a.attack}</span>
              <span aria-hidden className="h-4 rounded-r-sm bg-muted">
                <span className="block h-full rounded-r-[4px] bg-leak" style={{ width: `${Math.max(rate * 100, 0.5)}%` }} />
              </span>
              <span className="font-mono text-sm tabular-nums">
                {pct(rate)} succeeded <span className="text-muted-foreground">({a.succeeded}/{a.attempts})</span>
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Tile({ icon, label, detail, children }: { icon: ReactNode; label: string; detail: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
        {icon}
        {label}
      </p>
      <div className="mt-2">{children}</div>
      <p className="mt-1 text-sm text-muted-foreground">{detail}</p>
    </div>
  );
}

function Compare({ raw, masq }: { raw: string; masq: string }) {
  return (
    <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <span className="text-lg tabular-nums text-muted-foreground">
        <span className="sr-only">Without MasqAI: </span>
        <Swatch series="raw" />
        {raw}
      </span>
      <span aria-hidden className="text-muted-foreground">
        →
      </span>
      <span className="text-4xl font-semibold tabular-nums">
        <span className="sr-only">With MasqAI: </span>
        <Swatch series="masq" />
        {masq}
      </span>
    </p>
  );
}

function Swatch({ series }: { series: "raw" | "masq" }) {
  return (
    <span
      aria-hidden
      className={`mr-1.5 inline-block size-2.5 rounded-sm align-middle ${series === "raw" ? "bg-series-raw" : "bg-series-masq"}`}
    />
  );
}

function SeriesLegend() {
  return (
    <ul aria-label="Series" className="flex gap-4 text-sm">
      <li className="flex items-center">
        <Swatch series="raw" />
        Without MasqAI (raw)
      </li>
      <li className="flex items-center">
        <Swatch series="masq" />
        With MasqAI
      </li>
    </ul>
  );
}

function MetricChart({ metric, data }: { metric: Metric; data: Results }) {
  const colors = useThemeColors();
  const rows = data.cases.map((c) => ({ uc: ucLabel(c.id), title: c.title, raw: c.raw[metric.key], masqai: c.masqai[metric.key] }));
  return (
    <figure className="rounded-lg border bg-card p-4">
      <figcaption className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <span className="font-semibold">{metric.title}</span>
        <span className="text-sm text-muted-foreground">{metric.better}</span>
      </figcaption>
      <div className="h-60" role="img" aria-label={`${metric.title} per use case, raw versus MasqAI. Exact values are in the table below.`}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} barGap={2} barCategoryGap="24%" margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <CartesianGrid vertical={false} stroke={colors.border} />
            <XAxis dataKey="uc" tickLine={false} axisLine={{ stroke: colors.border }} tick={{ fill: colors["muted-foreground"], fontSize: 13 }} />
            <YAxis
              domain={metric.domain ?? [0, "auto"]}
              tickFormatter={metric.axis ?? metric.format}
              tickLine={false}
              axisLine={false}
              width={64}
              tick={{ fill: colors["muted-foreground"], fontSize: 13 }}
            />
            <Tooltip
              cursor={{ fill: colors.muted }}
              content={({ active, payload }) => {
                if (!active || !payload?.length) return null;
                const row = payload[0].payload as (typeof rows)[number];
                return (
                  <div className="rounded-md border bg-popover px-3 py-2 text-sm text-popover-foreground shadow-md">
                    <p className="font-medium">
                      {row.uc} · {row.title}
                    </p>
                    <p className="mt-1 flex items-center tabular-nums">
                      <Swatch series="raw" />
                      Raw: {metric.format(row.raw)}
                    </p>
                    <p className="flex items-center tabular-nums">
                      <Swatch series="masq" />
                      MasqAI: {metric.format(row.masqai)}
                    </p>
                  </div>
                );
              }}
            />
            <Bar dataKey="raw" name="Without MasqAI" fill={colors["series-raw"]} radius={[4, 4, 0, 0]} maxBarSize={24} isAnimationActive={false} />
            <Bar dataKey="masqai" name="With MasqAI" fill={colors["series-masq"]} radius={[4, 4, 0, 0]} maxBarSize={24} minPointSize={metric.labelMasq ? 2 : 0} isAnimationActive={false}>
              {metric.labelMasq ? (
                <LabelList
                  dataKey="masqai"
                  // Custom content: the default skips zero-height bars, and 0% is the point here.
                  content={({ x, y, width, value }) => (
                    <text
                      x={Number(x) + Number(width) / 2}
                      y={Number(y) - 6}
                      textAnchor="middle"
                      fill={colors.foreground}
                      fontSize={12}
                    >
                      {metric.format(Number(value))}
                    </text>
                  )}
                />
              ) : null}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </figure>
  );
}

function ResultsTable({ data }: { data: Results }) {
  return (
    <details className="rounded-lg border bg-card">
      <summary className="cursor-pointer px-4 py-3 font-medium">Show all values as a table</summary>
      <div className="overflow-x-auto px-4 pb-4">
        <table className="w-full min-w-[640px] text-left text-sm tabular-nums">
          <caption className="sr-only">Per-use-case metrics, raw versus MasqAI</caption>
          <thead className="text-muted-foreground">
            <tr className="border-b">
              <th scope="col" className="py-2 pr-3 font-medium">Use case</th>
              {METRICS.map((m) => (
                <th key={m.key} scope="col" className="py-2 pr-3 font-medium">
                  {m.title} (raw → MasqAI)
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.cases.map((c) => (
              <tr key={c.id} className="border-b last:border-0">
                <th scope="row" className="py-2 pr-3 font-medium">
                  {ucLabel(c.id)} {c.title}
                </th>
                {METRICS.map((m) => (
                  <td key={m.key} className="py-2 pr-3 font-mono">
                    {m.format(c.raw[m.key])} → {m.format(c.masqai[m.key])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
