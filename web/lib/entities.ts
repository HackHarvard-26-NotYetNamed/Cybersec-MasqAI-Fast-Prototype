import { AtSign, Folder, KeyRound, Server, Tag, UserRound, type LucideIcon } from "lucide-react";
import type { Entity, Replay, Step } from "./data";

export type ChipType = "PATH" | "KEY" | "EMAIL" | "HOST" | "USER" | "OTHER";

export const CHIP_STYLES: Record<ChipType, { label: string; icon: LucideIcon; className: string }> = {
  PATH: { label: "Path", icon: Folder, className: "text-ent-path border-ent-path/50 bg-ent-path/12" },
  KEY: { label: "Key", icon: KeyRound, className: "text-ent-key border-ent-key/50 bg-ent-key/12" },
  EMAIL: { label: "Email", icon: AtSign, className: "text-ent-email border-ent-email/50 bg-ent-email/12" },
  HOST: { label: "Host", icon: Server, className: "text-ent-host border-ent-host/50 bg-ent-host/12" },
  USER: { label: "Identity", icon: UserRound, className: "text-ent-user border-ent-user/50 bg-ent-user/12" },
  OTHER: { label: "Other", icon: Tag, className: "text-ent-other border-ent-other/50 bg-ent-other/12" },
};

export function chipType(type: string): ChipType {
  const t = type.toUpperCase();
  return t in CHIP_STYLES ? (t as ChipType) : "OTHER";
}

/** Type for a placeholder that is not in the replay's entity list, guessed from its label. */
export function typeFromPlaceholder(placeholder: string): ChipType {
  const label = placeholder.replace(/^<\$?/, "").replace(/_[0-9a-f]+>$/, "");
  if (/PATH/.test(label)) return "PATH";
  if (/EMAIL/.test(label)) return "EMAIL";
  if (/HOST/.test(label)) return "HOST";
  if (/KEY|TOKEN|JWT|SECRET|PASSWORD|DB_URL/.test(label)) return "KEY";
  if (/USER|IDENTITY|NAME|PHONE|CHAT|HANDLE/.test(label)) return "USER";
  return "OTHER";
}

export const PLACEHOLDER_RE = /<\$?[A-Z][A-Z0-9_]*_[0-9a-f]{4,}>/g;
export const COLLAPSE_RE = /…\[MASQ_BLOCK: ([^\]]*)\]…/g;

/** Replay-wide lookup tables, like the gateway's in-RAM mapping table. */
export type ReplayIndex = {
  byPlaceholder: Map<string, Entity>;
  secrets: Entity[]; // mask/partial entities, unique by value, longest value first
};

export function indexReplay(replay: Replay): ReplayIndex {
  const byPlaceholder = new Map<string, Entity>();
  const byValue = new Map<string, Entity>();
  for (const step of replay.steps) {
    for (const e of step.entities) {
      if (!byPlaceholder.has(e.placeholder)) byPlaceholder.set(e.placeholder, e);
      if (e.op !== "collapse" && !byValue.has(e.value)) byValue.set(e.value, e);
    }
  }
  const secrets = [...byValue.values()].sort((a, b) => b.value.length - a.value.length);
  return { byPlaceholder, secrets };
}

export function placeholderType(index: ReplayIndex, placeholder: string): ChipType {
  const e = index.byPlaceholder.get(placeholder);
  return e ? chipType(e.type) : typeFromPlaceholder(placeholder);
}

/** What the relay would have received without MasqAI: raw text, and real values in model output. */
export function unprotectedText(index: ReplayIndex, step: Step): string {
  if (step.role !== "assistant") return step.raw;
  return restorePlaceholders(index, step.sanitized);
}

export function restorePlaceholders(index: ReplayIndex, text: string): string {
  return text.replace(PLACEHOLDER_RE, (ph) => {
    const e = index.byPlaceholder.get(ph);
    return e && e.op !== "collapse" ? e.value : ph;
  });
}

export type Counts = { requests: number; exposed: number };

export function relayCounts(replay: Replay, upTo: number, protectedMode: boolean): Counts {
  const sent = replay.steps
    .slice(0, upTo + 1)
    .filter((s) => s.role !== "assistant" && (!protectedMode || !s.blocked));
  const exposed = new Set<string>();
  for (const s of sent)
    for (const e of s.entities) if (e.op !== "collapse" && (!protectedMode || e.missed)) exposed.add(e.value);
  return { requests: sent.length, exposed: exposed.size };
}

// ---------- segmentation ----------

export type Match<T> = { start: number; end: number; payload: T };

/** All non-overlapping occurrences, earliest first; at equal start the longest wins. */
export function findAll<T>(text: string, needles: { needle: string; payload: T }[]): Match<T>[] {
  const all: Match<T>[] = [];
  for (const { needle, payload } of needles) {
    if (!needle) continue;
    let i = text.indexOf(needle);
    while (i !== -1) {
      all.push({ start: i, end: i + needle.length, payload });
      i = text.indexOf(needle, i + needle.length);
    }
  }
  all.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Match<T>[] = [];
  let cursor = 0;
  for (const m of all) {
    if (m.start >= cursor) {
      out.push(m);
      cursor = m.end;
    }
  }
  return out;
}

export function findRegex(text: string, re: RegExp): Match<RegExpExecArray>[] {
  const out: Match<RegExpExecArray>[] = [];
  for (const m of text.matchAll(new RegExp(re.source, "g"))) {
    out.push({ start: m.index, end: m.index + m[0].length, payload: m as RegExpExecArray });
  }
  return out;
}
