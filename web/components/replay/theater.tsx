"use client";

import { useEffect, useEffectEvent, useMemo, useRef, useState, type ReactNode } from "react";
import { motion, useReducedMotion } from "motion/react";
import {
  Ban,
  ChevronLeft,
  ChevronRight,
  EyeOff,
  Laptop,
  ListChecks,
  Lock,
  Pause,
  Play,
  RadioTower,
  RotateCcw,
  ShieldCheck,
  ShieldHalf,
  ShieldOff,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { ReplayIndexSchema, ReplaySchema, useJson, type Replay, type Step } from "@/lib/data";
import { CHIP_STYLES, blockLabel, indexReplay, isApplied, relayCounts, sanitizedAsOf, type ChipType, type Counts, type ReplayIndex } from "@/lib/ops";
import { cn } from "@/lib/utils";
import { DataError, Loading } from "@/components/site/page-bits";
import { Drawer, DrawerContent, DrawerTitle, DrawerTrigger } from "@/components/ui/drawer";
import { PlaceholderChip, ReplacedMark, RestoredMark, SecretMark } from "./annotated-text";
import { DecisionPanel } from "./decision-panel";
import { StepView, type PaneMode } from "./step-view";

const ucLabel = (id: string) => id.match(/^uc(\d+)/i)?.[0].toUpperCase() ?? id;
const PANE_HEIGHT = "h-[min(64vh,680px)] min-h-[360px]";

export function ReplayTheater() {
  const index = useJson("/data/replays/index.json", ReplayIndexSchema);
  const [picked, setPicked] = useState(() => (typeof window === "undefined" ? "" : window.location.hash.slice(1)));
  // Follow the URL hash too (back button, edited URL, links to #uc…).
  useEffect(() => {
    const onHash = () => setPicked(window.location.hash.slice(1));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  if (index.status === "loading") return <Loading label="Loading replays" />;
  if (index.status === "error") return <DataError url={index.url} message={index.message} />;

  const replays = index.data;
  // Without a #hash, open UC2: the replay the pitch script talks over.
  const current = replays.find((r) => r.id === picked) ?? replays.find((r) => r.id === "uc2-db-path") ?? replays[0];
  const pick = (id: string) => {
    setPicked(id);
    history.replaceState(null, "", `#${id}`);
  };

  return (
    <div className="space-y-4">
      <div role="group" aria-label="Use case" className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
        {replays.map((r) => {
          const active = r.id === current.id;
          return (
            <button
              key={r.id}
              type="button"
              aria-pressed={active}
              onClick={() => pick(r.id)}
              className={cn(
                "rounded-md border px-3 py-2 text-left transition-colors hover:bg-accent",
                active ? "border-foreground/50 bg-accent" : "bg-card",
              )}
            >
              <span className="block font-mono text-sm text-muted-foreground">{ucLabel(r.id)}</span>
              <span className="block text-sm leading-snug font-medium">{r.title}</span>
            </button>
          );
        })}
      </div>
      <ReplayLoader key={current.id} file={`/data/replays/${current.file}`} />
    </div>
  );
}

function ReplayLoader({ file }: { file: string }) {
  const replay = useJson(file, ReplaySchema);
  if (replay.status === "loading") return <Loading label="Loading replay" />;
  if (replay.status === "error") return <DataError url={replay.url} message={replay.message} />;
  return <Player replay={replay.data} />;
}

function stepDelay(step: Step) {
  return 2200 + Math.min(2400, (step.raw.length + (step.toolCall?.argsSent.length ?? 0)) * 3) + (step.relinks.length ? 2600 : 0);
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

function caption(step: Step, unprotected: boolean): string {
  if (step.blocked) return `Blocked with HTTP ${step.blocked.status}: ${blockLabel(step.blocked.reason)}. Nothing reaches the untrusted model.`;
  const applied = step.ops.filter(isApplied);
  if (unprotected) {
    if (step.role === "assistant")
      return step.toolCall ? "The model saw the real values, so its tool call contains them too." : "Model response.";
    return applied.length
      ? `Without MasqAI the untrusted model receives all ${plural(applied.length, "flagged value")} verbatim.`
      : "Without MasqAI this is forwarded verbatim. Nothing sensitive in this one.";
  }
  if (step.relinks.length)
    return `Relink: an earlier masked fragment belongs to a newly found key. ${plural(new Set(step.relinks.flatMap((r) => r.stepsRewritten)).size, "earlier step")} rewritten to the <$…> form; the prompt cache breaks, on purpose.`;
  if (step.role === "assistant") {
    const call = step.toolCall;
    if (call && call.argsSent !== call.argsRestored)
      return "The tool call contains placeholders. MasqAI swaps the real values back in locally, so the command runs on real data.";
    if (call) return "A tool call with nothing to restore: it runs exactly as the model wrote it.";
    return "Model response, passed back unmodified. Placeholders in its text stay: proof the model never had the values.";
  }
  if (!step.ops.length) return "Nothing sensitive here: forwarded unchanged.";
  const count = (f: (o: Step["ops"][number]) => boolean) => applied.filter(f).length;
  const parts = [
    count((o) => o.source === "detector") && `detectors mask ${count((o) => o.source === "detector")}`,
    count((o) => o.source === "auto") && `auto masks copy ${count((o) => o.source === "auto")}`,
    count((o) => o.source === "model" && o.op === "mask") && `the security model masks ${count((o) => o.source === "model" && o.op === "mask")} the rules missed`,
    count((o) => o.op === "hide") && `hides ${plural(count((o) => o.op === "hide"), "block")} of intel`,
    count((o) => o.op === "replace") && `replaces ${count((o) => o.op === "replace")} intel detail${count((o) => o.op === "replace") === 1 ? "" : "s"}`,
  ].filter(Boolean);
  const notes = [
    step.ops.some((o) => o.verdict === "vetoed") && "vetoes a wrong auto mask",
    step.ops.some((o) => o.verdict === "left_as_is") && "leaves a copy inside a longer word alone",
    step.ops.some((o) => o.verdict === "rejected_invalid") && "fixes an invalid op in the retry round",
  ].filter(Boolean);
  const text = parts.join(", ");
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}.${notes.length ? ` The security model also ${notes.join(" and ")}.` : ""}`;
}

function Player({ replay }: { replay: Replay }) {
  const index = useMemo(() => indexReplay(replay), [replay]);
  const last = replay.steps.length - 1;
  const reduce = useReducedMotion();
  const [i, setI] = useState(0);
  // Auto mode: plays on its own, flips to "Without MasqAI" at the end to show the contrast, then loops.
  // Any key or control press hands over to manual.
  const [auto, setAuto] = useState(true);
  const [playing, setPlaying] = useState(!reduce);
  const [unprotected, setUnprotected] = useState(false);
  const [mobilePane, setMobilePane] = useState<"agent" | "untrusted">("untrusted");
  // A relink jumps the untrusted pane back to the first rewritten step, then returns.
  const [relinkFocus, setRelinkFocus] = useState<number | null>(null);

  useEffect(() => {
    if (!playing) return;
    const id = setTimeout(() => {
      const next = Math.min(i + 1, last);
      setI(next);
      if (next >= last) setPlaying(false);
    }, stepDelay(replay.steps[i]));
    return () => clearTimeout(id);
  }, [playing, i, last, replay]);

  useEffect(() => {
    if (!auto || reduce || playing || i < last) return;
    const flip = setTimeout(() => setUnprotected(true), 2500);
    const back = setTimeout(() => setUnprotected(false), 8500);
    const again = setTimeout(() => {
      setI(0);
      setPlaying(true);
    }, 10500);
    return () => {
      clearTimeout(flip);
      clearTimeout(back);
      clearTimeout(again);
    };
  }, [auto, reduce, playing, i, last]);

  useEffect(() => {
    const rewritten = replay.steps[i].relinks.flatMap((r) => r.stepsRewritten).filter((s) => s < i);
    if (!rewritten.length) return;
    const jump = setTimeout(() => setRelinkFocus(Math.min(...rewritten)), 350);
    const back = setTimeout(() => setRelinkFocus(null), 3000);
    return () => {
      clearTimeout(jump);
      clearTimeout(back);
      setRelinkFocus(null);
    };
  }, [i, replay]);

  const go = (n: number) => {
    setAuto(false);
    setPlaying(false);
    setI(Math.max(0, Math.min(last, n)));
  };
  const togglePlay = () => {
    setAuto(false);
    if (playing) return setPlaying(false);
    if (i >= last) setI(0);
    setPlaying(true);
  };

  // ←/→ step, space plays/pauses. Ignored while typing or when a control handles the key itself.
  const onKey = useEffectEvent((e: KeyboardEvent) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const target = e.target as HTMLElement | null;
    if (target?.closest("input, textarea, select, [contenteditable=true], [role=tab], [role=dialog]")) return;
    if (e.key === "ArrowRight") go(i + 1);
    else if (e.key === "ArrowLeft") go(i - 1);
    else if (e.key === " " && !target?.closest("button, a, [role=switch]")) togglePlay();
    else return;
    e.preventDefault();
  });
  useEffect(() => {
    const handler = (e: KeyboardEvent) => onKey(e);
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  const step = replay.steps[i];
  const visible = replay.steps.slice(0, i + 1);
  const counts = relayCounts(replay, i, !unprotected);

  return (
    <div className="space-y-4">
      {/* One compact card: what this replay is, the before/after switch, and the controls. On a projector the
          two panes below must start within the first screen. */}
      <div className="rounded-lg border bg-card p-3 sm:p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start">
          <div className="flex-1">
            <h2 className="text-xl font-semibold">
              <span className="mr-2 font-mono text-muted-foreground">{ucLabel(replay.id)}</span>
              {replay.title}
            </h2>
            <p className="mt-0.5 text-pretty text-muted-foreground">{replay.summary}</p>
          </div>
          <UnprotectedSwitch on={unprotected} onChange={(v) => { setAuto(false); setUnprotected(v); }} />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t pt-3">
          <ControlButton label={playing ? "Pause (space)" : "Play (space)"} onClick={togglePlay} primary>
            {playing ? <Pause aria-hidden className="size-4" /> : <Play aria-hidden className="size-4" />}
            <span>{playing ? "Pause" : i >= last ? "Replay" : "Play"}</span>
          </ControlButton>
          <ControlButton label="Previous step (left arrow)" onClick={() => go(i - 1)} disabled={i === 0}>
            <ChevronLeft aria-hidden className="size-4" />
          </ControlButton>
          <ControlButton label="Next step (right arrow)" onClick={() => go(i + 1)} disabled={i === last}>
            <ChevronRight aria-hidden className="size-4" />
          </ControlButton>
          <ControlButton label="Restart" onClick={() => go(0)} disabled={i === 0}>
            <RotateCcw aria-hidden className="size-4" />
          </ControlButton>
          <span className="font-mono text-sm text-muted-foreground tabular-nums">
            Step {i + 1} / {replay.steps.length}
          </span>
          {auto && !reduce ? (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-restored/50 bg-restored/10 px-2.5 py-0.5 text-sm text-restored">
              <span aria-hidden className="size-2 animate-pulse rounded-full bg-restored" />
              Auto-playing
            </span>
          ) : null}
          <span className="ml-auto hidden text-sm text-muted-foreground md:inline">
            Keys: <kbd className="rounded border px-1 font-mono">←</kbd> <kbd className="rounded border px-1 font-mono">→</kbd>{" "}
            <kbd className="rounded border px-1 font-mono">space</kbd>
          </span>
        </div>
        <Timeline steps={replay.steps} current={i} onPick={go} />
        <p aria-live="polite" className="mt-3 min-h-[1.5em] text-base text-pretty">
          {caption(step, unprotected)}
        </p>
      </div>

      {step.blocked && !unprotected ? (
        <div
          role="status"
          className="flex flex-wrap items-center gap-3 rounded-lg border-2 border-leak/70 bg-leak/10 px-4 py-3 font-mono text-lg font-semibold text-leak"
        >
          <Ban aria-hidden className="size-6" />
          BLOCKED · {step.blocked.status} · {blockLabel(step.blocked.reason)}
        </div>
      ) : null}

      <div className="flex items-center gap-2 xl:hidden">
        <div role="tablist" aria-label="Pane" className="grid flex-1 grid-cols-2 gap-1 rounded-lg border bg-muted p-1 md:hidden">
          {(["agent", "untrusted"] as const).map((p) => (
            <button
              key={p}
              role="tab"
              id={`tab-${p}`}
              aria-selected={mobilePane === p}
              aria-controls={`pane-${p}`}
              onClick={() => setMobilePane(p)}
              onKeyDown={(e) => {
                if (e.key === "ArrowLeft" || e.key === "ArrowRight") setMobilePane(p === "agent" ? "untrusted" : "agent");
              }}
              className={cn(
                "min-h-10 rounded-md text-sm font-medium",
                mobilePane === p ? "bg-card text-foreground shadow-sm" : "text-muted-foreground",
              )}
            >
              {p === "agent" ? "Agent" : "Untrusted model"}
            </button>
          ))}
        </div>
        <Drawer>
          <DrawerTrigger className="inline-flex min-h-11 items-center gap-2 rounded-lg border bg-card px-3 text-sm font-medium hover:bg-accent md:ml-auto">
            <ListChecks aria-hidden className="size-4" />
            Decisions ({step.ops.length + step.relinks.length})
          </DrawerTrigger>
          <DrawerContent className="max-h-[80vh]">
            <DrawerTitle className="sr-only">Decisions for step {i + 1}</DrawerTitle>
            <div className="flex max-h-[78vh] min-h-0 flex-col">
              <DecisionPanel step={step} stepNumber={i + 1} index={index} />
            </div>
          </DrawerContent>
        </Drawer>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-[1fr_1fr_320px]">
        <Pane
          id="agent"
          hiddenOnMobile={mobilePane !== "agent"}
          icon={<Laptop aria-hidden className="size-4" />}
          title="What your agent sent"
          subtitle="Raw, on your machine"
          focus={i}
          status={
            <p className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm text-muted-foreground">
              <Lock aria-hidden className="size-4" />
              Real values stay in gateway RAM on this machine
            </p>
          }
        >
          {visible.map((s, n) => (
            <AnimatedStep key={n}>
              <StepView step={s} stepIndex={n} mode="agent" index={index} current={n === i} />
            </AnimatedStep>
          ))}
        </Pane>
        <Pane
          id="untrusted"
          hiddenOnMobile={mobilePane !== "untrusted"}
          icon={<RadioTower aria-hidden className="size-4" />}
          title="What the untrusted model saw"
          subtitle={unprotected ? "Without MasqAI" : "Sanitized by MasqAI"}
          focus={relinkFocus ?? i}
          tone={unprotected ? "leak" : undefined}
          status={<Counter counts={counts} unprotected={unprotected} />}
        >
          <UntrustedSteps replay={replay} current={i} index={index} unprotected={unprotected} />
        </Pane>
        {/* Absolutely filled, so the panel matches the panes' height instead of stretching the row. */}
        <div className="relative hidden xl:block">
          <div className="absolute inset-0 flex flex-col overflow-hidden rounded-lg border bg-card">
            <DecisionPanel step={step} stepNumber={i + 1} index={index} />
          </div>
        </div>
      </div>

      <HygieneStrip headers={replay.headersStripped} fields={replay.pseudonymized} />
      <Legend />
    </div>
  );
}

function UntrustedSteps({
  replay,
  current,
  index,
  unprotected,
}: {
  replay: Replay;
  current: number;
  index: ReplayIndex;
  unprotected: boolean;
}) {
  const mode: PaneMode = unprotected ? "unprotected" : "untrusted";
  const visible = replay.steps.slice(0, current + 1).map((s, n) => ({ s, n }));
  const shown = visible.filter(({ s }) => unprotected || !s.blocked);
  const blockedNow = !unprotected && replay.steps[current].blocked;
  return (
    <>
      {shown.map(({ s, n }) => {
        const asOf = unprotected ? null : sanitizedAsOf(replay, n, current);
        return (
          <AnimatedStep key={n}>
            <StepView
              step={s}
              stepIndex={n}
              mode={mode}
              index={index}
              current={n === current}
              sanitized={asOf?.text}
              rewrittenTo={asOf?.rewrittenTo}
            />
          </AnimatedStep>
        );
      })}
      {blockedNow && shown.length === 0 ? (
        <AnimatedStep>
          <div className="flex min-h-72 flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed border-leak/60 bg-leak/6 p-6 text-center">
            <Ban aria-hidden className="size-12 text-leak" />
            <p className="font-mono text-2xl font-bold tracking-tight text-leak">BLOCKED</p>
            <p className="text-lg font-medium">0 requests reached the untrusted model</p>
            <p className="max-w-sm text-muted-foreground">MasqAI fails closed: the agent gets an error, the untrusted model gets nothing.</p>
          </div>
        </AnimatedStep>
      ) : blockedNow ? (
        <p className="flex items-center gap-2 rounded-lg border border-dashed border-leak/60 p-3 font-medium text-leak">
          <Ban aria-hidden className="size-4" /> Blocked: this request never reached the untrusted model.
        </p>
      ) : null}
    </>
  );
}

function AnimatedStep({ children }: { children: ReactNode }) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      initial={reduce ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}

function Pane({
  id,
  title,
  subtitle,
  icon,
  status,
  children,
  focus,
  hiddenOnMobile,
  tone,
}: {
  id: string;
  title: string;
  subtitle: string;
  icon: ReactNode;
  status: ReactNode;
  children: ReactNode;
  /** Step index to keep in view. */
  focus: number;
  hiddenOnMobile: boolean;
  tone?: "leak";
}) {
  const scroller = useRef<HTMLDivElement>(null);
  // Keep the focused step in view inside the pane, without scrolling the page.
  useEffect(() => {
    const el = scroller.current;
    const target =
      el?.querySelector<HTMLElement>(`[data-step="${focus}"]`) ?? (el?.lastElementChild as HTMLElement | null);
    if (!el || !target) return;
    // Measured from rects: offsetTop is relative to the animating (transformed) wrapper mid-entrance.
    const box = target.getBoundingClientRect();
    const offset = box.top - el.getBoundingClientRect().top + el.scrollTop;
    const top = box.height > el.clientHeight ? offset - 12 : offset + box.height - el.clientHeight + 12;
    el.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
  }, [focus]);

  return (
    <section
      id={`pane-${id}`}
      role="tabpanel"
      aria-labelledby={`pane-${id}-title`}
      className={cn(
        "flex-col overflow-hidden rounded-lg border bg-muted/40 md:flex",
        hiddenOnMobile ? "hidden" : "flex",
        tone === "leak" && "border-leak/60",
      )}
    >
      <header className="space-y-2 border-b bg-card px-4 py-3">
        <div className="flex flex-wrap items-baseline gap-x-3">
          <h3 id={`pane-${id}-title`} className="flex items-center gap-2 font-semibold">
            {icon}
            {title}
          </h3>
          <p className={cn("text-sm text-muted-foreground", tone === "leak" && "font-medium text-leak")}>{subtitle}</p>
        </div>
        {status}
      </header>
      <div
        ref={scroller}
        tabIndex={0}
        aria-label={`${title}: transcript`}
        className={cn("relative space-y-3 overflow-y-auto p-3 sm:p-4", PANE_HEIGHT)}
      >
        {children}
      </div>
    </section>
  );
}

function Counter({ counts, unprotected }: { counts: Counts; unprotected: boolean }) {
  const bad = counts.exposed > 0;
  const Icon = bad ? TriangleAlert : ShieldCheck;
  const text =
    !unprotected && counts.requests === 0 && counts.blocked > 0
      ? "0 requests reached the untrusted model"
      : `Untrusted model received ${plural(counts.requests, "request")} · ${plural(counts.exposed, "value")} exposed`;
  return (
    <p
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-sm tabular-nums",
        bad ? "border-leak/50 bg-leak/10 text-leak" : "border-restored/50 bg-restored/10 text-restored",
      )}
    >
      <Icon aria-hidden className="size-4 shrink-0" />
      {text}
    </p>
  );
}

function HygieneStrip({ headers, fields }: { headers: string[]; fields: string[] }) {
  const Chip = ({ children }: { children: string }) => (
    <li className="rounded border px-1.5 font-mono text-sm text-muted-foreground line-through decoration-2">
      <span className="sr-only">removed: </span>
      {children}
    </li>
  );
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg border bg-card px-4 py-3 text-sm">
      <span className="flex items-center gap-2 font-medium">
        <ShieldHalf aria-hidden className="size-4" /> Request hygiene
      </span>
      {headers.length === 0 && fields.length === 0 ? (
        <span className="text-muted-foreground">Nothing was forwarded, so nothing needed stripping.</span>
      ) : (
        <>
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="text-muted-foreground">Headers stripped:</span>
            <ul className="flex flex-wrap gap-1.5">
              {headers.map((h) => (
                <Chip key={h}>{h}</Chip>
              ))}
            </ul>
          </span>
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="text-muted-foreground">Pseudonymized:</span>
            <ul className="flex flex-wrap gap-1.5">
              {fields.map((f) => (
                <Chip key={f}>{f}</Chip>
              ))}
            </ul>
            <span className="text-muted-foreground">→ masq-…</span>
          </span>
        </>
      )}
    </div>
  );
}

function UnprotectedSwitch({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      onClick={() => onChange(!on)}
      className={cn(
        "inline-flex shrink-0 items-center gap-3 self-start rounded-lg border px-3 py-2 text-left transition-colors",
        on ? "border-leak/60 bg-leak/10" : "bg-background hover:bg-accent",
      )}
    >
      <span aria-hidden className={cn("relative h-6 w-11 rounded-full border transition-colors", on ? "border-leak bg-leak/80" : "border-input bg-muted")}>
        <span className={cn("absolute top-0.5 size-4.5 rounded-full bg-background shadow transition-[left]", on ? "left-5.5" : "left-0.5")} />
      </span>
      <span>
        <span className="flex items-center gap-1.5 font-medium">
          {on ? <ShieldOff aria-hidden className="size-4 text-leak" /> : <ShieldCheck aria-hidden className="size-4" />}
          Without MasqAI
        </span>
        <span className="block text-sm text-muted-foreground">{on ? "Showing the unprotected baseline" : "Show the before"}</span>
      </span>
    </button>
  );
}

function ControlButton({
  label,
  onClick,
  disabled,
  primary,
  children,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  primary?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "inline-flex min-h-10 min-w-10 items-center justify-center gap-2 rounded-md border px-3 text-sm font-medium transition-colors disabled:opacity-40",
        primary ? "border-transparent bg-primary text-primary-foreground hover:bg-primary/85" : "hover:bg-accent",
      )}
    >
      {children}
    </button>
  );
}

function Timeline({ steps, current, onPick }: { steps: Step[]; current: number; onPick: (n: number) => void }) {
  return (
    <ol aria-label="Steps" className="mt-3 flex gap-1">
      {steps.map((s, n) => {
        const label = `Step ${n + 1}: ${s.role === "user" ? "prompt" : s.role === "tool" ? "tool output" : s.role === "system" ? "system prompt" : "model response"}${s.blocked ? ", blocked" : ""}${s.relinks.length ? ", relink" : ""}`;
        return (
          <li key={n} className="flex-1">
            <button
              type="button"
              aria-label={label}
              title={label}
              aria-current={n === current ? "step" : undefined}
              onClick={() => onPick(n)}
              className="group flex h-8 w-full items-center"
            >
              <span
                className={cn(
                  "h-2 w-full rounded-full transition-colors",
                  s.blocked
                    ? "bg-leak/70"
                    : s.relinks.length
                      ? "bg-model"
                      : n <= current
                        ? s.role === "assistant"
                          ? "bg-foreground/45"
                          : "bg-foreground"
                        : "bg-foreground/15 group-hover:bg-foreground/30",
                  n === current && "h-3 ring-2 ring-ring ring-offset-2 ring-offset-card",
                )}
              />
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function Legend() {
  const types: ChipType[] = ["PATH", "KEY", "EMAIL", "HOST", "USER"];
  return (
    <div className="rounded-lg border bg-card p-4">
      <h3 className="mb-2 text-sm font-medium text-muted-foreground">Legend</h3>
      <ul className="flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[15px]">
        <li>
          <SecretMark text="raw secret" type="KEY" />
        </li>
        <li>
          <SecretMark text="leaked" type="KEY" leaked />
        </li>
        {types.map((t) => (
          <li key={t}>
            <PlaceholderChip placeholder={`<${t}_…>`} type={t} alias={false} />
            <span className="ml-1.5 font-sans text-sm text-muted-foreground">{CHIP_STYLES[t].label} masked</span>
          </li>
        ))}
        <li>
          <PlaceholderChip placeholder="<$KEY_…>" type="KEY" alias />
          <span className="ml-1.5 font-sans text-sm text-muted-foreground">alias (partial form)</span>
        </li>
        <li className="flex items-center gap-1.5 font-sans text-sm text-model">
          <Sparkles aria-hidden className="size-4" /> found by the security model
        </li>
        <li className="flex items-center gap-1.5 font-sans text-sm text-collapsed">
          <EyeOff aria-hidden className="size-4" /> intel hidden
        </li>
        <li>
          <ReplacedMark text="intel replaced" reason="Legend example: a detail swapped for a neutral word." />
        </li>
        <li>
          <RestoredMark text="restored locally" />
        </li>
      </ul>
    </div>
  );
}
