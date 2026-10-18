"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { AnimatePresence, motion } from "motion/react";
import { STARTS, STOPS, SPEAKER_TONE, clock } from "@/lib/pitch";
import { cn } from "@/lib/utils";

/*
 * Pitch mode, for presenting from this site. Press P (or open any page with ?pitch) to start.
 *   Page Down / Page Up (what a presentation clicker sends), or N / B: next / previous stop of the script
 *   C: the speaker's cue card · P: leave pitch mode
 * A small strip shows who speaks, the part, and the time. State lives in sessionStorage, so a page change
 * or reload keeps the place.
 */

type State = { active: boolean; index: number; startedAt: number | null };
const KEY = "masq-pitch";
const OFF: State = { active: false, index: 0, startedAt: null };

let state: State = load();
const listeners = new Set<() => void>();

function load(): State {
  try {
    return { ...OFF, ...JSON.parse(sessionStorage.getItem(KEY) ?? "{}") };
  } catch {
    return OFF;
  }
}

function set(next: Partial<State>) {
  state = { ...state, ...next };
  try {
    sessionStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    // Private mode or blocked storage: pitch mode still works for this page.
  }
  listeners.forEach((l) => l());
}

const subscribe = (l: () => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

export function PitchMode() {
  const pitch = useSyncExternalStore(subscribe, () => state, () => OFF);
  const router = useRouter();
  const pathname = usePathname();
  const [cues, setCues] = useState(false);
  const [now, setNow] = useState(0);
  const [hint, setHint] = useState(false);
  const pendingScroll = useRef(false);

  // ?pitch on any page turns it on.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).has("pitch") && !state.active) set({ active: true, startedAt: Date.now() });
  }, []);

  useEffect(() => {
    if (!pitch.active) return;
    const tick = () => setNow(Date.now());
    tick();
    const id = setInterval(tick, 500);
    return () => clearInterval(id);
  }, [pitch.active]);

  useEffect(() => {
    if (!pitch.active) return;
    const show = setTimeout(() => setHint(true), 0);
    const hide = setTimeout(() => setHint(false), 4500);
    return () => {
      clearTimeout(show);
      clearTimeout(hide);
    };
  }, [pitch.active]);

  // After moving to a stop, bring its section into view once the page has rendered it.
  useEffect(() => {
    if (!pitch.active || !pendingScroll.current) return;
    const stop = STOPS[pitch.index];
    if (pathname !== stop.href) return;
    pendingScroll.current = false;
    let tries = 0;
    const place = () => {
      if (!stop.anchor) return window.scrollTo({ top: 0, behavior: "smooth" });
      const el = document.getElementById(stop.anchor);
      if (!el) {
        if (tries++ < 40) requestAnimationFrame(place);
        return;
      }
      window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - 72, behavior: "smooth" });
    };
    requestAnimationFrame(place);
  }, [pitch.active, pitch.index, pathname]);

  useEffect(() => {
    const go = (index: number) => {
      const i = Math.max(0, Math.min(STOPS.length - 1, index));
      set({ index: i });
      pendingScroll.current = true;
      const stop = STOPS[i];
      router.push(stop.href + (stop.anchor ? `#${stop.anchor}` : ""), { scroll: false });
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      const target = e.target as HTMLElement | null;
      if (target?.closest("input, textarea, select, [contenteditable=true]")) return;
      const key = e.key.toLowerCase();
      if (key === "p") {
        if (state.active) {
          set({ active: false });
          setCues(false);
        } else {
          set({ active: true, startedAt: state.startedAt ?? Date.now() });
        }
        return;
      }
      if (!state.active) return;
      if (e.key === "PageDown" || key === "n") go(state.index + 1);
      else if (e.key === "PageUp" || key === "b") go(state.index - 1);
      else if (key === "c") setCues((v) => !v);
      else if (key === "t") set({ startedAt: Date.now() });
      else if (e.key === "Escape") setCues(false);
      else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [router]);

  if (!pitch.active) return null;
  const stop = STOPS[pitch.index];
  const elapsed = pitch.startedAt && now ? Math.max(0, (now - pitch.startedAt) / 1000) : 0;
  const late = elapsed > STARTS[pitch.index] + stop.seconds;

  return (
    <div className="fixed bottom-4 left-4 z-50 flex max-w-[min(480px,calc(100vw-2rem))] flex-col items-start gap-2 print:hidden">
      <AnimatePresence>
        {cues ? (
          <motion.div
            key="cues"
            initial={{ y: 8, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 8, opacity: 0 }}
            className="w-full rounded-xl border bg-card/95 p-4 shadow-lg backdrop-blur"
          >
            <p className="text-sm text-muted-foreground">
              {stop.speaker} · {stop.title}
            </p>
            <ul className="mt-2 space-y-1.5">
              {stop.cues.map((cue) => (
                <li key={cue} className="flex gap-2 text-[15px] leading-snug">
                  <span aria-hidden className={cn("mt-1.5 size-2 shrink-0 rounded-full", SPEAKER_TONE[stop.speaker])} />
                  {cue}
                </li>
              ))}
            </ul>
            <p className="mt-3 font-medium text-restored">→ {stop.handoff}</p>
          </motion.div>
        ) : null}
      </AnimatePresence>
      <div
        role="status"
        aria-label={`Pitch mode: part ${pitch.index + 1} of ${STOPS.length}, ${stop.speaker}, ${stop.title}`}
        className="flex items-center gap-2.5 rounded-full border bg-card/90 py-1.5 pr-4 pl-2 text-sm shadow-lg backdrop-blur"
      >
        <span className="flex gap-1" aria-hidden>
          {STOPS.map((s, i) => (
            <span key={i} className={cn("h-1.5 w-4 rounded-full", i === pitch.index ? SPEAKER_TONE[s.speaker] : i < pitch.index ? "bg-foreground/40" : "bg-foreground/15")} />
          ))}
        </span>
        <span className="font-semibold">{stop.speaker}</span>
        <span className="text-muted-foreground">{stop.title}</span>
        <span className={cn("font-mono tabular-nums", late ? "text-replaced" : "text-muted-foreground")}>{clock(elapsed)}</span>
      </div>
      <AnimatePresence>
        {hint ? (
          <motion.p key="hint" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="rounded-md bg-card/90 px-2 py-1 font-mono text-xs text-muted-foreground">
            PgDn/N next · PgUp/B back · C cues · T reset timer · P exit
          </motion.p>
        ) : null}
      </AnimatePresence>
    </div>
  );
}
