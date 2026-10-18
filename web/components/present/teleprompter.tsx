"use client";

import { ChevronLeft, ChevronRight, Monitor, Pause, Play, RotateCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { STARTS, STOPS, SPEAKER_TONE, TOTAL_SECONDS, clock } from "@/lib/pitch";
import { cn } from "@/lib/utils";

/** Cue cards on a speaker's phone: whose turn, what to say, how long. Not linked from the site. */
export function Teleprompter() {
  const [index, setIndex] = useState(0);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [pausedAt, setPausedAt] = useState<number | null>(null);
  const [now, setNow] = useState(0);
  const [full, setFull] = useState(false);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);

  // Keep the phone's screen on while the cards are open, where the browser allows it.
  useEffect(() => {
    let lock: { release: () => Promise<void> } | null = null;
    const nav = navigator as Navigator & { wakeLock?: { request: (t: "screen") => Promise<{ release: () => Promise<void> }> } };
    nav.wakeLock?.request("screen").then((l) => (lock = l)).catch(() => {});
    return () => void lock?.release().catch(() => {});
  }, []);

  const running = startedAt !== null && pausedAt === null;
  const elapsed = startedAt === null || !now ? 0 : ((pausedAt ?? now) - startedAt) / 1000;
  const stop = STOPS[index];
  const end = STARTS[index] + stop.seconds;
  const late = elapsed > end;
  const go = (i: number) => {
    setIndex(Math.max(0, Math.min(STOPS.length - 1, i)));
    setFull(false);
  };
  const toggle = () => {
    if (startedAt === null) return setStartedAt(Date.now());
    if (pausedAt === null) return setPausedAt(Date.now());
    setStartedAt(startedAt + (Date.now() - pausedAt));
    setPausedAt(null);
  };

  return (
    // Full screen over the site's header and footer: on a phone, nothing else should compete for the space.
    <div className="fixed inset-0 z-[60] overflow-y-auto bg-background">
    <div className="mx-auto flex min-h-dvh max-w-xl flex-col gap-3 px-4 py-3">
      <div className="flex items-center gap-3 rounded-xl border bg-card p-3">
        <button type="button" onClick={toggle} aria-label={running ? "Pause the timer" : "Start the timer"} className="grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground">
          {running ? <Pause aria-hidden className="size-5" /> : <Play aria-hidden className="size-5" />}
        </button>
        <div className="min-w-0 flex-1">
          <p className={cn("font-mono text-3xl font-semibold tabular-nums", late && running ? "text-replaced" : "")}>{clock(elapsed)}</p>
          <p className="text-sm text-muted-foreground">
            this part ends at {clock(end)} · total {clock(TOTAL_SECONDS)}
          </p>
        </div>
        <button type="button" onClick={() => { setStartedAt(null); setPausedAt(null); }} aria-label="Reset the timer" className="grid size-10 place-items-center rounded-full border">
          <RotateCcw aria-hidden className="size-4" />
        </button>
      </div>

      <ol className="flex gap-1.5" aria-label="Parts">
        {STOPS.map((s, i) => (
          <li key={i} className="flex-1">
            <button type="button" onClick={() => go(i)} aria-current={i === index ? "step" : undefined} className="w-full text-left">
              <span className={cn("block h-1.5 rounded-full", i === index ? SPEAKER_TONE[s.speaker] : i < index ? "bg-foreground/40" : "bg-foreground/15")} />
              <span className={cn("mt-1 block truncate text-xs", i === index ? "font-semibold" : "text-muted-foreground")}>{s.speaker}</span>
            </button>
          </li>
        ))}
      </ol>

      <section aria-live="polite" className="flex-1 rounded-xl border bg-card p-4">
        <p className="flex items-center gap-2">
          <span className={cn("size-3 rounded-full", SPEAKER_TONE[stop.speaker])} aria-hidden />
          <span className="text-2xl font-semibold">{stop.speaker}</span>
          <span className="text-muted-foreground">· {stop.title}</span>
        </p>
        <p className="mt-1 flex items-center gap-1.5 text-sm text-muted-foreground">
          <Monitor aria-hidden className="size-4" />
          On screen: {stop.href === "/" ? "Home" : stop.href}
          {stop.anchor ? ` → ${stop.anchor}` : ""} · {stop.seconds} s
        </p>
        {full ? (
          <div className="mt-4 space-y-3 text-lg leading-relaxed">
            {stop.lines.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
        ) : (
          <ul className="mt-3 space-y-2.5">
            {stop.cues.map((cue) => (
              <li key={cue} className="flex gap-3 text-lg leading-snug">
                <span aria-hidden className={cn("mt-2 size-2.5 shrink-0 rounded-full", SPEAKER_TONE[stop.speaker])} />
                {cue}
              </li>
            ))}
          </ul>
        )}
        <p className="mt-4 text-xl font-semibold text-restored">→ {stop.handoff}</p>
        <button type="button" onClick={() => setFull((v) => !v)} className="mt-4 rounded-md border px-3 py-1.5 text-sm text-muted-foreground">
          {full ? "Show the cues" : "Show the full lines"}
        </button>
      </section>

      <div className="sticky bottom-0 -mx-4 grid grid-cols-2 gap-3 border-t bg-background/95 px-4 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] backdrop-blur">
        <button type="button" onClick={() => go(index - 1)} disabled={index === 0} className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl border bg-card text-lg font-medium disabled:opacity-40">
          <ChevronLeft aria-hidden className="size-5" /> Back
        </button>
        <button type="button" onClick={() => go(index + 1)} disabled={index === STOPS.length - 1} className="inline-flex min-h-14 items-center justify-center gap-2 rounded-xl bg-primary text-lg font-medium text-primary-foreground disabled:opacity-40">
          Next <ChevronRight aria-hidden className="size-5" />
        </button>
      </div>
    </div>
    </div>
  );
}
