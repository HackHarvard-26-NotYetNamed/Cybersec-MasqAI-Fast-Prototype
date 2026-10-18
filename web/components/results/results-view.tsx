"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { ArrowDown, Check, Clock3, ExternalLink, FlaskConical, MousePointer2, ShieldAlert, X } from "lucide-react";
import { ResultsSchema, useJson, type Condition, type ConditionMetrics, type Results } from "@/lib/data";
import { DataError, Loading } from "@/components/site/page-bits";

const pct = (value: number) => `${Math.round(value * 100)}%`;
const number = (value: number) => Math.round(value).toLocaleString("en-US");
const duration = (value: number) => value >= 1000 ? `${(value / 1000).toFixed(1)}s` : `${number(value)}ms`;
const title = (condition: Condition) => condition.kind === "raw" ? "Raw" : condition.security?.model?.split("/").pop() ?? condition.label;
const shortModel = (value?: string) => value?.split("/").pop()?.replace(/\b\w/g, (c) => c.toUpperCase()) ?? "Unknown model";

type MetricKey = "leakRate" | "taskSuccess" | "avgTokens" | "p50LatencyMs";
type Selected = { condition: Condition; caseTitle: string; caseId: string; metrics: ConditionMetrics };

export function ResultsView() {
  const results = useJson("/data/results.json", ResultsSchema);
  if (results.status === "loading") return <Loading label="Loading evaluation results" />;
  if (results.status === "error") return <DataError url={results.url} message={results.message} />;
  return <ResultsBody data={results.data} />;
}

function ResultsBody({ data }: { data: Results }) {
  const [selected, setSelected] = useState<Selected | null>(null);
  const conditions = useMemo(() => data.conditions.filter((condition) => data.cases.some((item) => item.conditions[condition.id])), [data]);
  const all = conditions.flatMap((condition) => data.cases.map((item) => item.conditions[condition.id]).filter(Boolean));
  const average = (key: MetricKey) => all.length ? all.reduce((sum, metrics) => sum + metrics[key], 0) / all.length : 0;
  const masqai = conditions.filter((condition) => condition.kind === "masqai");

  return (
    <div className="relative space-y-7">
      <section className="overflow-hidden rounded-lg border bg-grid bg-card/70 p-5 sm:p-7">
        <div className="flex flex-col justify-between gap-7 lg:flex-row lg:items-end">
          <div className="max-w-2xl">
            <p className="font-mono text-xs tracking-[0.18em] text-muted-foreground uppercase">Measurement console / {data.runsPerCase} runs per case</p>
            <h2 className="mt-3 text-3xl font-semibold tracking-tight sm:text-5xl">The choice is visible.</h2>
            <p className="mt-3 max-w-xl text-base text-muted-foreground sm:text-lg">Raw traffic shows the exposure baseline. Each MasqAI column shows what changes when a different security model makes the decision.</p>
          </div>
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border bg-border sm:grid-cols-4">
            <Summary label="Conditions" value={String(conditions.length)} />
            <Summary label="Use cases" value={String(data.cases.length)} />
            <Summary label="Leak avg" value={pct(average("leakRate"))} />
            <Summary label="Sandbox" value={data.sandbox} />
          </div>
        </div>
      </section>

      <section aria-labelledby="conditions-heading" className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div><p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">Three views of the same work</p><h2 id="conditions-heading" className="mt-1 text-2xl font-semibold">Condition board</h2></div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground"><MousePointer2 aria-hidden className="size-4" /> Select a cell for run profile</p>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {conditions.map((condition) => <ConditionCard key={condition.id} condition={condition} cases={data.cases} />)}
        </div>
      </section>

      <section aria-labelledby="matrix-heading" className="overflow-hidden rounded-lg border bg-card">
        <div className="flex flex-wrap items-end justify-between gap-3 border-b p-5"><div><p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">Case by condition</p><h2 id="matrix-heading" className="mt-1 text-2xl font-semibold">Exposure matrix</h2></div><Legend /></div>
        <div className="overflow-x-auto">
          <div className="min-w-[760px] p-4 sm:p-5">
            <div className="grid grid-cols-[minmax(150px,1.1fr)_repeat(3,minmax(170px,1fr))] gap-2 text-xs text-muted-foreground"><div className="px-3 py-2">Use case</div>{conditions.map((condition) => <div key={condition.id} className="px-3 py-2 font-mono uppercase">{title(condition)}</div>)}</div>
            {data.cases.map((item) => <div key={item.id} className="mt-2 grid grid-cols-[minmax(150px,1.1fr)_repeat(3,minmax(170px,1fr))] gap-2"><div className="flex min-h-28 flex-col justify-center rounded-md border bg-background px-3 py-3"><span className="font-mono text-xs text-muted-foreground">{item.id}</span><strong className="mt-1 text-sm">{item.title}</strong></div>{conditions.map((condition) => { const metrics = item.conditions[condition.id]; return metrics ? <MetricCell key={condition.id} condition={condition} metrics={metrics} onClick={() => setSelected({ condition, caseTitle: item.title, caseId: item.id, metrics })} /> : <div key={condition.id} className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">No measurement</div>; })}</div>)}
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
        <div className="rounded-lg border bg-card p-5 sm:p-6"><p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">How to read this</p><h2 className="mt-2 text-xl font-semibold">Local, remote, and none are different operating modes.</h2><div className="mt-5 grid gap-3 sm:grid-cols-3"><ReadCard label="Raw / none" text="The model sees unprotected content. This is the exposure baseline." tone="raw" /><ReadCard label="MasqAI / local" text="The security model runs locally, keeping policy decisions close to the gateway." tone="local" /><ReadCard label="MasqAI / remote" text="The security model is remote. Compare its protection against added latency and failure." tone="remote" /></div></div>
        <div className="rounded-lg border bg-card p-5 sm:p-6"><p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">Run metadata</p><dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-5 gap-y-3 text-sm"><dt className="text-muted-foreground">Security models</dt><dd>{masqai.length ? masqai.map((condition) => shortModel(condition.security?.model)).join(" / ") : "None reported"}</dd><dt className="text-muted-foreground">Untrusted model</dt><dd>{data.untrustedModel}</dd><dt className="text-muted-foreground">Generated</dt><dd>{formatDate(data.generatedAt)}</dd><dt className="text-muted-foreground">Agent</dt><dd>{data.agent}</dd></dl></div>
      </section>

      {data.placeholder ? <p className="rounded-md border border-dashed p-3 font-mono text-sm text-muted-foreground"><FlaskConical aria-hidden className="mr-2 inline size-4" />Self-test data is marked as placeholder.</p> : null}
      {selected ? <FocusPanel selected={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  );
}

function Summary({ label, value }: { label: string; value: string }) { return <div className="bg-card px-3 py-2.5"><p className="font-mono text-[10px] tracking-wide text-muted-foreground uppercase">{label}</p><p className="mt-1 text-sm font-semibold">{value}</p></div>; }

function ConditionCard({ condition, cases }: { condition: Condition; cases: Results["cases"] }) { const values = cases.map((item) => item.conditions[condition.id]).filter(Boolean); const leak = values.reduce((n, item) => n + item.leakRate, 0) / values.length; const success = values.reduce((n, item) => n + item.taskSuccess, 0) / values.length; return <div className={`rounded-md border p-4 ${condition.kind === "raw" ? "border-series-raw/60 bg-series-raw/5" : "border-series-masq/60 bg-series-masq/5"}`}><div className="flex items-start justify-between gap-3"><div><span className={`inline-flex rounded-sm px-2 py-1 font-mono text-[10px] font-bold uppercase ${condition.kind === "raw" ? "bg-series-raw/15 text-series-raw" : "bg-series-masq/15 text-series-masq"}`}>{mode(condition)}</span><h3 className="mt-3 text-lg font-semibold">{title(condition)}</h3><p className="mt-1 truncate text-xs text-muted-foreground" title={condition.label}>{condition.label}</p></div><ShieldAlert aria-hidden className="size-5 text-muted-foreground" /></div><div className="mt-5 grid grid-cols-2 gap-3"><MiniMetric label="leak rate" value={pct(leak)} bad={leak > 0} /><MiniMetric label="task success" value={pct(success)} /></div></div>; }
function mode(condition: Condition) { if (condition.kind === "raw") return "none"; const provider = condition.security?.provider?.toLowerCase() ?? ""; return provider.includes("local") || provider.includes("ollama") ? "local" : "remote"; }
function MiniMetric({ label, value, bad }: { label: string; value: string; bad?: boolean }) { return <div className="border-l-2 border-current/30 pl-2"><p className="text-xs text-muted-foreground">{label}</p><p className={`mt-1 text-xl font-semibold tabular-nums ${bad ? "text-leak" : ""}`}>{value}</p></div>; }
function MetricCell({ condition, metrics, onClick }: { condition: Condition; metrics: ConditionMetrics; onClick: () => void }) { const leak = metrics.leakRate > 0; return <button type="button" onClick={onClick} className={`group min-h-28 rounded-md border p-3 text-left transition hover:-translate-y-0.5 hover:border-foreground/50 hover:shadow-md ${leak ? "border-leak/50 bg-leak/5" : "border-restored/40 bg-restored/5"}`}><div className="flex items-center justify-between gap-2"><span className="font-mono text-[10px] uppercase text-muted-foreground">{title(condition)}</span><ExternalLink aria-hidden className="size-3.5 opacity-0 transition group-hover:opacity-100" /></div><div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2"><MetricLine label="leak" value={pct(metrics.leakRate)} danger={leak} /><MetricLine label="success" value={pct(metrics.taskSuccess)} /><MetricLine label="tokens" value={number(metrics.avgTokens)} /><MetricLine label="p50" value={duration(metrics.p50LatencyMs)} /></div><p className="mt-3 text-[11px] text-muted-foreground">{metrics.runs ?? "?"} measured runs · click to focus</p></button>; }
function MetricLine({ label, value, danger }: { label: string; value: string; danger?: boolean }) { return <div><p className="text-[10px] text-muted-foreground uppercase">{label}</p><p className={`font-mono text-sm font-semibold ${danger ? "text-leak" : ""}`}>{value}</p></div>; }
function Legend() { return <div className="flex flex-wrap gap-3 text-xs text-muted-foreground"><span className="flex items-center gap-1.5"><i className="size-2.5 rounded-sm bg-restored" />no measured leak</span><span className="flex items-center gap-1.5"><i className="size-2.5 rounded-sm bg-leak" />leak present</span><span className="flex items-center gap-1.5"><i className="size-2.5 rounded-sm bg-collapsed" />blocked runs are counted</span></div>; }
function ReadCard({ label, text, tone }: { label: string; text: string; tone: string }) { return <div className={`border-l-2 p-3 ${tone === "raw" ? "border-series-raw" : tone === "local" ? "border-restored" : "border-series-masq"}`}><p className="font-mono text-xs font-semibold uppercase">{label}</p><p className="mt-2 text-sm text-muted-foreground">{text}</p></div>; }
function FocusPanel({ selected, onClose }: { selected: Selected; onClose: () => void }) { const { metrics, condition } = selected; return <div className="fixed inset-0 z-40 flex items-end justify-center bg-foreground/20 p-3 backdrop-blur-sm sm:items-center"><section role="dialog" aria-modal="true" aria-labelledby="focus-title" className="w-full max-w-xl rounded-lg border bg-card p-5 shadow-2xl sm:p-6"><div className="flex items-start justify-between gap-4"><div><p className="font-mono text-xs tracking-[0.16em] text-muted-foreground uppercase">Focused run profile</p><h2 id="focus-title" className="mt-2 text-2xl font-semibold">{selected.caseTitle}</h2><p className="mt-1 text-sm text-muted-foreground">{selected.caseId} / {condition.label}</p></div><button type="button" onClick={onClose} aria-label="Close run profile" className="rounded-md border p-2 hover:bg-accent"><X aria-hidden className="size-4" /></button></div><div className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4"><ProfileMetric icon={<ShieldAlert aria-hidden />} label="Leak rate" value={pct(metrics.leakRate)} bad={metrics.leakRate > 0} /><ProfileMetric icon={<Check aria-hidden />} label="Task success" value={pct(metrics.taskSuccess)} /><ProfileMetric icon={<ArrowDown aria-hidden />} label="Avg tokens" value={number(metrics.avgTokens)} /><ProfileMetric icon={<Clock3 aria-hidden />} label="P50 latency" value={duration(metrics.p50LatencyMs)} /></div><div className="mt-5 border-t pt-4 text-sm"><p className="font-medium">Representative runs</p>{metrics.examples?.length ? <div className="mt-3 grid gap-2">{metrics.examples.map((example, index) => <div key={index} className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-background px-3 py-2"><span className="font-mono text-xs text-muted-foreground">run {String(index + 1).padStart(2, "0")}</span><span className={`font-medium ${example.status === "leak" ? "text-leak" : example.status === "ok" ? "text-restored" : "text-muted-foreground"}`}>{example.status}</span><span className="text-xs text-muted-foreground">{example.tokens.toLocaleString("en-US")} tokens{example.latencyMs ? ` · ${duration(example.latencyMs)}` : ""}</span></div>)}</div> : <p className="mt-2 text-muted-foreground">This publication predates representative run profiles. Republish the campaign to include them.</p>}<p className="mt-4 text-muted-foreground">Prompts, canaries, and raw traces stay out of the public result file.</p><div className="mt-4 grid gap-2 sm:grid-cols-3"><Stat label="Blocked" value={String(metrics.blocked ?? 0)} /><Stat label="Expected blocks" value={String(metrics.expectedBlocks ?? 0)} /><Stat label="Tool calls vetoed" value={String(metrics.toolCallsVetoed ?? 0)} /></div></div></section></div>; }
function ProfileMetric({ icon, label, value, bad }: { icon: ReactNode; label: string; value: string; bad?: boolean }) { return <div className="rounded-md border bg-background p-3"><span className="text-muted-foreground">{icon}</span><p className="mt-2 text-xs text-muted-foreground">{label}</p><p className={`mt-1 font-mono text-lg font-semibold ${bad ? "text-leak" : ""}`}>{value}</p></div>; }
function Stat({ label, value }: { label: string; value: string }) { return <div className="flex items-center justify-between rounded-md border px-3 py-2"><span className="text-muted-foreground">{label}</span><strong className="font-mono">{value}</strong></div>; }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : `${date.toLocaleDateString("en-US", { dateStyle: "medium" })} UTC`; }
