import { ChevronsDownUp, RotateCcw, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import type { Entity } from "@/lib/data";
import {
  CHIP_STYLES,
  COLLAPSE_RE,
  PLACEHOLDER_RE,
  chipType,
  findAll,
  findRegex,
  placeholderType,
  type ChipType,
  type Match,
  type ReplayIndex,
} from "@/lib/entities";
import { cn } from "@/lib/utils";

// ---------- marks ----------

export function PlaceholderChip({ placeholder, type }: { placeholder: string; type: ChipType }) {
  const style = CHIP_STYLES[type];
  const Icon = style.icon;
  const alias = placeholder.startsWith("<$");
  return (
    <span
      className={cn(
        "mx-px inline-flex items-center gap-1 rounded border px-1.5 align-baseline leading-normal whitespace-nowrap",
        style.className,
      )}
    >
      <Icon aria-hidden className="size-[0.85em] shrink-0" />
      <span className="sr-only">{`masked ${alias ? "partial " : ""}${style.label.toLowerCase()}: `}</span>
      {placeholder}
    </span>
  );
}

export function SecretMark({ text, type, leaked }: { text: string; type: ChipType; leaked?: boolean }) {
  const Icon = leaked ? TriangleAlert : CHIP_STYLES[type].icon;
  return (
    <mark className="rounded-sm bg-leak/15 px-0.5 text-leak underline decoration-leak/70 decoration-2 underline-offset-[3px] [overflow-wrap:anywhere]">
      <span className="sr-only">{leaked ? "leaked secret: " : `real ${CHIP_STYLES[type].label.toLowerCase()}: `}</span>
      <span className="whitespace-nowrap">
        <Icon aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />
        {text.slice(0, 1)}
      </span>
      {text.slice(1)}
    </mark>
  );
}

export function RestoredMark({ text }: { text: string }) {
  return (
    <mark className="rounded-sm bg-restored/15 px-0.5 text-restored underline decoration-restored/70 decoration-2 underline-offset-[3px] [overflow-wrap:anywhere]">
      <span className="sr-only">restored locally: </span>
      <span className="whitespace-nowrap">
        <RotateCcw aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />
        {text.slice(0, 1)}
      </span>
      {text.slice(1)}
    </mark>
  );
}

function CollapseBar({ summary }: { summary: string }) {
  return (
    <span className="my-1.5 flex items-start gap-2 rounded border border-dashed border-collapsed/60 bg-collapsed/10 px-2.5 py-1.5 whitespace-normal text-collapsed">
      <ChevronsDownUp aria-hidden className="mt-[0.2em] size-[1em] shrink-0" />
      <span>
        <span className="font-semibold">Collapsed:</span> {summary}
      </span>
    </span>
  );
}

function CollapsedRegion({ children }: { children: ReactNode }) {
  return (
    <span className="my-1.5 block border-l-2 border-dashed border-collapsed/70 pl-3">
      <span className="flex items-center gap-1.5 font-sans text-sm text-collapsed">
        <ChevronsDownUp aria-hidden className="size-3.5" />
        Collapsed before sending
      </span>
      {children}
    </span>
  );
}

// ---------- segmentation helpers ----------

type InlineMark = { kind: "secret"; entity: Entity } | { kind: "chip"; placeholder: string };

function renderInline(
  text: string,
  { secrets, mark, chips, index }: { secrets: Entity[]; mark: "secret" | "leak" | "restored"; chips: boolean; index: ReplayIndex },
  keyPrefix: string,
): ReactNode[] {
  const matches: Match<InlineMark>[] = [
    ...findAll(
      text,
      secrets.map((entity) => ({ needle: entity.value, payload: { kind: "secret", entity } as InlineMark })),
    ),
    ...(chips
      ? findRegex(text, PLACEHOLDER_RE).map((m) => ({
          ...m,
          payload: { kind: "chip", placeholder: m.payload[0] } as InlineMark,
        }))
      : []),
  ];
  matches.sort((a, b) => a.start - b.start || b.end - a.end);

  const out: ReactNode[] = [];
  let cursor = 0;
  for (const m of matches) {
    if (m.start < cursor) continue;
    if (m.start > cursor) out.push(text.slice(cursor, m.start));
    const key = `${keyPrefix}-${m.start}`;
    if (m.payload.kind === "secret") {
      const value = text.slice(m.start, m.end);
      out.push(
        mark === "restored" ? (
          <RestoredMark key={key} text={value} />
        ) : (
          <SecretMark key={key} text={value} type={chipType(m.payload.entity.type)} leaked={mark === "leak"} />
        ),
      );
    } else {
      out.push(<PlaceholderChip key={key} placeholder={m.payload.placeholder} type={placeholderType(index, m.payload.placeholder)} />);
    }
    cursor = m.end;
  }
  if (cursor < text.length) out.push(text.slice(cursor));
  return out;
}

/** Split text around block-level matches, dropping one newline on each side so blocks don't double-space. */
function splitBlocks<T>(text: string, matches: Match<T>[]) {
  const parts: ({ kind: "text"; text: string } | { kind: "block"; match: Match<T> })[] = [];
  let cursor = 0;
  for (const m of matches) {
    let before = text.slice(cursor, m.start);
    if (before.endsWith("\n")) before = before.slice(0, -1);
    if (before) parts.push({ kind: "text", text: before });
    parts.push({ kind: "block", match: m });
    cursor = m.end;
    if (text[cursor] === "\n") cursor += 1;
  }
  if (cursor < text.length) parts.push({ kind: "text", text: text.slice(cursor) });
  return parts;
}

const PRE = "font-mono text-[15px] leading-[1.85] whitespace-pre-wrap [overflow-wrap:anywhere] md:text-base";

// ---------- public views ----------

/** Agent side: real values highlighted in red; regions the gateway collapsed are outlined. */
export function RawText({ text, entities, index }: { text: string; entities: Entity[]; index: ReplayIndex }) {
  const secrets = entities.filter((e) => e.op !== "collapse").sort((a, b) => b.value.length - a.value.length);
  const collapses = findAll(
    text,
    entities.filter((e) => e.op === "collapse").map((e) => ({ needle: e.value, payload: e })),
  );
  const opts = { secrets, mark: "secret" as const, chips: true, index };
  return (
    <p className={PRE}>
      {splitBlocks(text, collapses).map((part, i) =>
        part.kind === "text" ? (
          renderInline(part.text, opts, `t${i}`)
        ) : (
          <CollapsedRegion key={`c${i}`}>
            {renderInline(text.slice(part.match.start, part.match.end), opts, `c${i}`)}
          </CollapsedRegion>
        ),
      )}
    </p>
  );
}

/** Relay side with MasqAI: placeholders as chips, collapsed blocks as bars, misses in red. */
export function SanitizedText({ text, entities, index }: { text: string; entities: Entity[]; index: ReplayIndex }) {
  const missed = entities.filter((e) => e.missed && e.op !== "collapse");
  const opts = { secrets: missed, mark: "leak" as const, chips: true, index };
  return (
    <p className={PRE}>
      {splitBlocks(text, findRegex(text, COLLAPSE_RE)).map((part, i) =>
        part.kind === "text" ? (
          renderInline(part.text, opts, `t${i}`)
        ) : (
          <CollapseBar key={`c${i}`} summary={part.match.payload[1]} />
        ),
      )}
    </p>
  );
}

/** Relay side without MasqAI: the raw text, every known secret marked as leaked. */
export function LeakedText({ text, index }: { text: string; index: ReplayIndex }) {
  return <p className={PRE}>{renderInline(text, { secrets: index.secrets, mark: "leak", chips: false, index }, "l")}</p>;
}

/** Agent side of a tool call: values swapped back in from placeholders, marked green. */
export function RestoredText({ text, index }: { text: string; index: ReplayIndex }) {
  return <p className={PRE}>{renderInline(text, { secrets: index.secrets, mark: "restored", chips: true, index }, "r")}</p>;
}
