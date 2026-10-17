import { AtSign, Folder, KeyRound, Server, Tag, UserRound, type LucideIcon } from "lucide-react";
import { BLOCK_REASONS, type Op, type Replay, type Step } from "./data";

export type ChipType = "PATH" | "KEY" | "EMAIL" | "HOST" | "USER" | "OTHER";

export const CHIP_STYLES: Record<ChipType, { label: string; icon: LucideIcon; className: string }> = {
  PATH: { label: "Path", icon: Folder, className: "text-ent-path border-ent-path/55 bg-ent-path/12" },
  KEY: { label: "Key", icon: KeyRound, className: "text-ent-key border-ent-key/55 bg-ent-key/12" },
  EMAIL: { label: "Email", icon: AtSign, className: "text-ent-email border-ent-email/55 bg-ent-email/12" },
  HOST: { label: "Host", icon: Server, className: "text-ent-host border-ent-host/55 bg-ent-host/12" },
  USER: { label: "Identity", icon: UserRound, className: "text-ent-user border-ent-user/55 bg-ent-user/12" },
  OTHER: { label: "Other", icon: Tag, className: "text-ent-other border-ent-other/55 bg-ent-other/12" },
};

/** Chip color for a type or placeholder label (`<OR_KEY_…>` → KEY, `<USERNAME_…>` → USER). */
export function chipType(typeOrPlaceholder: string | null | undefined): ChipType {
  const label = (typeOrPlaceholder ?? "").toUpperCase().replace(/^<\$?/, "").replace(/_[0-9A-F]+>$/, "");
  if (label in CHIP_STYLES) return label as ChipType;
  if (/PATH|DIR|FILE/.test(label)) return "PATH";
  if (/EMAIL/.test(label)) return "EMAIL";
  if (/HOST|DEVICE|MACHINE/.test(label)) return "HOST";
  if (/KEY|TOKEN|JWT|SECRET|PASSWORD|CRED|PEM/.test(label)) return "KEY";
  if (/USER|IDENTITY|NAME|PHONE|CHAT|HANDLE/.test(label)) return "USER";
  return "OTHER";
}

export const PLACEHOLDER_RE = /<\$?[A-Z][A-Z0-9_]*_[0-9a-f]{4,}>/g;
export const HIDDEN_RE = /…\[hidden: ([^\]]*)\]…/g;

export const blockLabel = (reason: keyof typeof BLOCK_REASONS) => BLOCK_REASONS[reason];

export const isApplied = (o: Op) => o.verdict === "applied";

/** Replay-wide lookup tables, like the gateway's mapping table. */
export type ReplayIndex = {
  byPlaceholder: Map<string, Op>;
  /** Values of applied mask/replace ops, unique, longest first: what "Without MasqAI" marks as leaked. */
  leakable: Op[];
};

export function indexReplay(replay: Replay): ReplayIndex {
  const byPlaceholder = new Map<string, Op>();
  const byValue = new Map<string, Op>();
  for (const step of replay.steps) {
    for (const o of step.ops) {
      if (o.placeholder && o.op === "mask" && !byPlaceholder.has(o.placeholder)) byPlaceholder.set(o.placeholder, o);
      if (isApplied(o) && (o.op === "mask" || o.op === "replace") && o.value && !byValue.has(o.value)) byValue.set(o.value, o);
    }
    for (const o of step.ops)
      if (o.op === "relink" && o.placeholder && !byPlaceholder.has(o.placeholder)) byPlaceholder.set(o.placeholder, o);
  }
  const leakable = [...byValue.values()].sort((a, b) => (b.value?.length ?? 0) - (a.value?.length ?? 0));
  return { byPlaceholder, leakable };
}

export function placeholderInfo(index: ReplayIndex, placeholder: string) {
  const o = index.byPlaceholder.get(placeholder);
  return { type: chipType(o?.type ?? placeholder), alias: placeholder.startsWith("<$") };
}

/** What the untrusted model would have received without MasqAI. */
export function unprotectedText(index: ReplayIndex, step: Step): string {
  if (step.role !== "assistant") return step.raw;
  return step.sanitized.replace(PLACEHOLDER_RE, (ph) => index.byPlaceholder.get(ph)?.value ?? ph);
}

/** A step's sanitized text as of `current`: relinks from later steps rewrite earlier placeholders. */
export function sanitizedAsOf(replay: Replay, stepIndex: number, current: number) {
  let text = replay.steps[stepIndex].sanitized;
  const rewrittenTo: string[] = [];
  for (let k = stepIndex + 1; k <= current && k < replay.steps.length; k++) {
    for (const r of replay.steps[k].relinks) {
      if (!r.stepsRewritten.includes(stepIndex) || !text.includes(r.fromPlaceholder)) continue;
      text = text.split(r.fromPlaceholder).join(r.toPlaceholder);
      rewrittenTo.push(r.toPlaceholder);
    }
  }
  return { text, rewrittenTo };
}

const sendsContext = (s: Step) => s.role === "user" || s.role === "tool";

export type Counts = { requests: number; exposed: number; blocked: number };

export function relayCounts(replay: Replay, upTo: number, protectedMode: boolean): Counts {
  const seen = replay.steps.slice(0, upTo + 1);
  const forwarded = seen.filter((s) => !protectedMode || !s.blocked);
  const exposed = new Set<string>();
  for (const s of forwarded) {
    if (s.role === "assistant") continue;
    for (const o of s.ops) {
      if (!isApplied(o) || !o.value || o.op === "relink" || o.op === "unmask") continue;
      // With MasqAI a value counts only if it still reached upstream verbatim.
      if (!protectedMode || (o.op !== "hide" && containsWord(s.sanitized, o.value))) exposed.add(o.value);
    }
  }
  return {
    requests: forwarded.filter(sendsContext).length,
    exposed: exposed.size,
    blocked: seen.filter((s) => s.blocked).length,
  };
}

// ---------- segmentation ----------

const WORD = /[A-Za-z0-9_]/;

/** The gateway's auto-mask rule: a match inside a longer word (letter, digit or _ next to it) doesn't count. */
export function atWordBoundary(text: string, start: number, end: number): boolean {
  const needle = text.slice(start, end);
  const before = start > 0 && WORD.test(needle[0]) && WORD.test(text[start - 1]);
  const after = end < text.length && WORD.test(needle[needle.length - 1]) && WORD.test(text[end]);
  return !before && !after;
}

export function containsWord(text: string, value: string): boolean {
  for (let i = text.indexOf(value); i !== -1; i = text.indexOf(value, i + 1))
    if (atWordBoundary(text, i, i + value.length)) return true;
  return false;
}

export type Match<T> = { start: number; end: number; payload: T };

/** All non-overlapping occurrences, earliest first; at equal start the longest wins. */
export function findAll<T>(
  text: string,
  needles: { needle: string; payload: T }[],
  { wordBoundary = false } = {},
): Match<T>[] {
  const all: Match<T>[] = [];
  for (const { needle, payload } of needles) {
    if (!needle) continue;
    let i = text.indexOf(needle);
    while (i !== -1) {
      if (!wordBoundary || atWordBoundary(text, i, i + needle.length)) all.push({ start: i, end: i + needle.length, payload });
      i = text.indexOf(needle, i + needle.length);
    }
  }
  return nonOverlapping(all);
}

export function findRegex(text: string, re: RegExp): Match<RegExpExecArray>[] {
  return [...text.matchAll(new RegExp(re.source, "g"))].map((m) => ({
    start: m.index,
    end: m.index + m[0].length,
    payload: m as RegExpExecArray,
  }));
}

export function nonOverlapping<T>(matches: Match<T>[]): Match<T>[] {
  const sorted = [...matches].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Match<T>[] = [];
  let cursor = 0;
  for (const m of sorted) {
    if (m.start >= cursor) {
      out.push(m);
      cursor = m.end;
    }
  }
  return out;
}
