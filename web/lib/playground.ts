/**
 * The in-browser playground (/try): the gateway's deterministic layer, run locally in the page.
 *
 * Rules and categories come from detector-rules.json, generated from masqai/rules and masqai/policy.py by
 * scripts/export_web_rules.py, so the browser and the gateway share one source of truth. What runs here:
 * detector rules, the generic key=value rule, this-machine and custom values, the user's protect
 * categories, and automatic masking of every exact copy at word boundaries. What doesn't: the security
 * model (it needs the user's machine), so names, addresses and intel are only caught in the real gateway.
 * Nothing typed here leaves the browser.
 */
import data from "./detector-rules.json";

export type Category = { id: string; label: string; kind: "secret" | "intel"; description: string; types: string[] };
export type Selection = Record<string, boolean>;
export type Finding = { start: number; end: number; value: string; type: string; source: string };
export type Entity = { value: string; type: string; placeholder: string; source: string; category: string | null };
export type Segment = { text: string; entity?: Entity };

export const CATEGORIES = data.categories as Category[];
export const ALL_ON: Selection = Object.fromEntries(CATEGORIES.map((c) => [c.id, true]));

// ---------- categories (policy.py) ----------

const BY_TYPE = new Map(CATEGORIES.flatMap((c) => c.types.map((t) => [t, c.id] as const)));
const SUFFIXES = data.suffixes.map((s) => ({ re: new RegExp(s.source), category: s.category }));

export function categoryOf(type: string): string | null {
  const name = type.toUpperCase();
  return BY_TYPE.get(name) ?? SUFFIXES.find((s) => s.re.test(name))?.category ?? null;
}

/** A type MasqAI can't place in a category stays protected, as in the gateway. */
export function isProtected(selection: Selection, type: string): boolean {
  const category = categoryOf(type);
  return category === null || selection[category] !== false;
}

// ---------- detectors (detectors.py) ----------

const MIN_VALUE_LENGTH = 3;
const PLACEHOLDER = /<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>/;

function templated(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    PLACEHOLDER.test(value) ||
    /^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^{}]+\}|%[A-Za-z_][A-Za-z0-9_]*%|\*+)$/.test(value) ||
    value.startsWith("{{") ||
    value.startsWith("<") ||
    (value.startsWith("__") && value.endsWith("__")) ||
    value.includes("...") ||
    value.includes("…") ||
    (value.includes("<") && value.includes(">")) ||
    ["your", "my-", "my_", "example"].some((p) => lower.startsWith(p))
  );
}

type Rule = { name: string; type: string; hits: (text: string) => Iterable<[number, number]> };

function patternRule(r: (typeof data.rules)[number]): Rule {
  const ignore = r.ignore.map((i) => new RegExp(`^(?:${i.source})$`, i.flags));
  return {
    name: r.name,
    type: r.type,
    *hits(text) {
      const re = new RegExp(r.source, r.flags + "gd");
      for (const m of text.matchAll(re)) {
        const span = m.indices?.[r.group];
        const value = m[r.group];
        if (!span || value === undefined || span[1] <= span[0]) continue;
        if (r.group !== 0 && (templated(value) || ignore.some((p) => p.test(value)))) continue;
        yield [span[0], span[1]];
      }
    },
  };
}

function keyValueRule(): Rule {
  const kv = data.keyvalue;
  const names = kv.names.map((n) => n.toLowerCase());
  const long = [...new Set(names.filter((n) => n.length >= 5))].sort((a, b) => b.length - a.length);
  const short = [...new Set(names.filter((n) => n.length < 5))].sort((a, b) => b.length - a.length);
  const ignore = new Set([...kv.ignore_values.map((v) => v.toLowerCase()), ...names]);
  const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/;
  const attribute = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/;
  const lineStart = /^[ \t]*(?:export[ \t]+|-[ \t]+)?$/;

  const secretKey = (key: string) => {
    const k = key.toLowerCase();
    return long.some((n) => k.endsWith(n)) || short.some((n) => k === n || (k.endsWith(n) && "_.-".includes(k[k.length - n.length - 1])));
  };

  return {
    name: "generic_key_value",
    type: "SECRET",
    *hits(text) {
      const re = new RegExp(kv.source, kv.flags + "gd");
      let position = 0;
      for (;;) {
        re.lastIndex = position;
        const m = re.exec(text);
        if (!m || !m.groups || !m.indices?.groups) return;
        const g = m.groups, at = m.indices.groups;
        const quoted = g.value !== undefined;
        const value = quoted ? g.value : (g.bare ?? "").replace(/[.,]+$/, "");
        const start = quoted ? at.value![0] : at.bare![0];
        const resume = g.q ? at.q![0] : at.bare ? at.bare[0] : m.index + m[0].length;
        if (accept(m, g, value, start, quoted)) {
          yield [start, start + value.length];
          position = start + value.length;
        } else {
          position = Math.max(resume, m.index + 1);
        }
      }

      function accept(m: RegExpExecArray, g: Record<string, string | undefined>, value: string, start: number, quoted: boolean): boolean {
        if (!g.key || !secretKey(g.key) || !value) return false;
        if (ignore.has(value.toLowerCase()) || new Set(value).size === 1 || templated(value)) return false;
        const letters = /[A-Za-z]/.test(value), digits = /[0-9]/.test(value);
        if (value.length < (letters && digits ? kv.min_length_mixed : kv.min_length)) return false;
        if (quoted) return !(value.includes(" ") && !digits);
        const end = start + value.length;
        if (end < text.length && "([".includes(text[end])) return false;
        if (value.startsWith(".") || attribute.test(value)) return false;
        if (identifier.test(value)) {
          const keyAt = m.indices!.groups!.key![0];
          const lineHead = text.slice(text.lastIndexOf("\n", keyAt - 1) + 1, keyAt);
          const assignment = lineStart.test(lineHead);
          const inCall = (lineHead.match(/\(/g)?.length ?? 0) > (lineHead.match(/\)/g)?.length ?? 0);
          if (!(assignment || (letters && digits && !inCall))) return false;
          if (!digits && (value.includes("_") || /^[A-Z]/.test(value))) return false;
        }
        return true;
      }
    },
  };
}

const RULES: Rule[] = [...data.rules.map(patternRule)];
// Generic and broad rules go last, after email (load_rules' order).
RULES.push(keyValueRule());

export function scan(text: string): Finding[] {
  const taken: [number, number][] = [];
  const found: Finding[] = [];
  for (const rule of RULES) {
    for (const [start, end] of rule.hits(text)) {
      const value = text.slice(start, end);
      if (value.length < MIN_VALUE_LENGTH || value.startsWith("<")) continue;
      if (taken.some(([a, b]) => a < end && start < b)) continue;
      taken.push([start, end]);
      found.push({ start, end, value, type: rule.type, source: `detector: ${rule.name}` });
    }
  }
  return found;
}

// ---------- masking ----------

export type Fixed = { value: string; type: string; source: string; always?: boolean };

const word = (c: string | undefined) => !!c && /[A-Za-z0-9_]/.test(c);

/**
 * Mask `text` like the gateway's deterministic layer: detector hits and fixed values (this machine, custom)
 * become entities; every exact copy of an entity is masked at word boundaries, longest first.
 * `placeholders` keeps each value's placeholder stable across edits.
 */
export function mask(text: string, selection: Selection, fixed: Fixed[], placeholders: Map<string, string>) {
  const entities = new Map<string, Entity>();
  const add = (value: string, type: string, source: string) => {
    if (value.length < MIN_VALUE_LENGTH || entities.has(value)) return;
    let placeholder = placeholders.get(value);
    if (!placeholder) {
      const id = Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) => b.toString(16).padStart(2, "0")).join("");
      placeholder = `<${type}_${id}>`;
      placeholders.set(value, placeholder);
    }
    entities.set(value, { value, type, placeholder, source, category: categoryOf(type) });
  };
  const notProtected: Finding[] = [];
  for (const f of scan(text)) {
    if (isProtected(selection, f.type)) add(f.value, f.type, f.source);
    else notProtected.push(f);
  }
  for (const f of fixed) {
    if (f.value && (f.always || isProtected(selection, f.type)) && text.includes(f.value)) add(f.value, f.type, f.source);
  }

  const spans: { start: number; end: number; entity: Entity }[] = [];
  for (const entity of [...entities.values()].sort((a, b) => b.value.length - a.value.length)) {
    let at = text.indexOf(entity.value);
    while (at !== -1) {
      const end = at + entity.value.length;
      const boundary = !(word(entity.value[0]) && word(text[at - 1])) && !(word(entity.value.at(-1)) && word(text[end]));
      if (boundary && !spans.some((s) => s.start < end && at < s.end)) spans.push({ start: at, end, entity });
      at = text.indexOf(entity.value, at + 1);
    }
  }
  spans.sort((a, b) => a.start - b.start);
  const segments: Segment[] = [];
  let cursor = 0;
  for (const s of spans) {
    if (s.start > cursor) segments.push({ text: text.slice(cursor, s.start) });
    segments.push({ text: s.entity.placeholder, entity: s.entity });
    cursor = s.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor) });
  return { segments, entities: [...entities.values()], masked: spans.length, notProtected };
}

// ---------- the tool-call check (sanitize.clearly_local_command) ----------

const LOCAL = new Set(["cat", "ls", "head", "tail", "grep", "fgrep", "wc", "pwd", "cd", "echo", "find", "sqlite3", "sort", "uniq", "cut"]);
const NETWORK = /\b(curl|wget|scp|rsync|ssh|nc|ncat|netcat|socat|ftp|telnet)\b|https?:\/\/|\/dev\/(tcp|udp)/;
export const REJECTED_COMMAND = 'echo "MasqAI: the user\'s security profile rejected this execution"';

/** The gateway's fast path: every part of the command starts with a known-local program. */
export function clearlyLocal(command: string): boolean {
  if (!command.trim() || ["$(", "`", "/dev/tcp", "/dev/udp", "\n", "\\"].some((m) => command.includes(m))) return false;
  const parts = command.replace(/<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>/g, "MASKED_VALUE").split(/&&|;|\|/);
  return parts.every((part) => {
    const words = part.trim().split(/\s+/);
    if (!words[0] || !LOCAL.has(words[0]) || /[<>()&]/.test(part)) return false;
    if (words[0] === "find" && words.some((w) => w.startsWith("-exec") || w.startsWith("-ok"))) return false;
    if (words[0] === "sqlite3" && words.slice(1).some((w) => w.startsWith(".") || w.startsWith("-") || /load_extension/i.test(w))) return false;
    return true;
  });
}

export type ToolVerdict =
  | { kind: "no-placeholder"; command: string }
  | { kind: "restored"; command: string }
  | { kind: "rejected"; command: string }
  | { kind: "inspect"; command: string };

/** What the gateway does with a tool call the untrusted model sends back (`table`: placeholder → real value). */
export function checkToolCall(command: string, table: Map<string, string>): ToolVerdict {
  const placeholders = command.match(/<\$?[A-Z][A-Z0-9_]*_[a-f0-9]{8}>/g) ?? [];
  const restored = command.replace(/<\$?([A-Z][A-Z0-9_]*_[a-f0-9]{8})>/g, (ph, inner) => table.get(`<${inner}>`) ?? ph);
  if (!placeholders.length) return { kind: "no-placeholder", command };
  if (clearlyLocal(command)) return { kind: "restored", command: restored };
  // In the gateway the local security model decides; a network command carrying a secret is what it rejects.
  if (NETWORK.test(command)) return { kind: "rejected", command: REJECTED_COMMAND };
  return { kind: "inspect", command };
}
