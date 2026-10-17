"use client";

import { ArrowLeftRight, EyeOff, RotateCcw, Sparkles, TriangleAlert } from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import type { ReactNode } from "react";
import type { Op } from "@/lib/data";
import {
  CHIP_STYLES,
  HIDDEN_RE,
  PLACEHOLDER_RE,
  chipType,
  findAll,
  findRegex,
  isApplied,
  nonOverlapping,
  placeholderInfo,
  type ChipType,
  type Match,
  type ReplayIndex,
} from "@/lib/ops";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

const PRE = "font-mono text-[15px] leading-[1.9] whitespace-pre-wrap [overflow-wrap:anywhere] md:text-base";

// ---------- marks ----------

export function PlaceholderChip({
  placeholder,
  type,
  alias = placeholder.startsWith("<$"),
  model = false,
  flash = false,
}: {
  placeholder: string;
  type: ChipType;
  alias?: boolean;
  model?: boolean;
  flash?: boolean;
}) {
  const reduce = useReducedMotion();
  const style = CHIP_STYLES[type];
  const Icon = style.icon;
  const body = (
    <>
      <Icon aria-hidden className="size-[0.85em] shrink-0" />
      <span className="sr-only">{`masked ${alias ? "partial form of a " : ""}${style.label.toLowerCase()}${model ? ", found by the security model" : ""}: `}</span>
      {placeholder}
      {model ? <Sparkles aria-hidden className="size-[0.8em] shrink-0 text-model" /> : null}
    </>
  );
  const className = cn(
    "mx-px inline-flex items-center gap-1 rounded border px-1.5 align-baseline leading-normal whitespace-nowrap",
    style.className,
    alias && "border-2 border-dashed",
    model && "ring-2 ring-model/70",
  );
  const chip = alias ? (
    <Tooltip>
      <TooltipTrigger type="button" className={cn(className, "cursor-help font-mono")}>
        {body}
      </TooltipTrigger>
      <TooltipContent>Partial form: an alias of a known value, restored to the full value.</TooltipContent>
    </Tooltip>
  ) : (
    <span className={className}>{body}</span>
  );
  if (!flash || reduce) return chip;
  return (
    <motion.span
      className="inline-block rounded"
      initial={{ scale: 1.35, boxShadow: "0 0 0 4px var(--model)" }}
      animate={{ scale: 1, boxShadow: "0 0 0 0px var(--model)" }}
      transition={{ duration: 0.9, ease: "easeOut" }}
    >
      {chip}
    </motion.span>
  );
}

function Glued({ icon, text }: { icon: ReactNode; text: string }) {
  // Keep the icon on the same line as the first character so a wrap can't orphan it.
  return (
    <>
      <span className="whitespace-nowrap">
        {icon}
        {text.slice(0, 1)}
      </span>
      {text.slice(1)}
    </>
  );
}

export function SecretMark({ text, type, leaked }: { text: string; type: ChipType; leaked?: boolean }) {
  const Icon = leaked ? TriangleAlert : CHIP_STYLES[type].icon;
  return (
    <mark className="rounded-sm bg-leak/15 px-0.5 text-leak underline decoration-leak/70 decoration-2 underline-offset-[3px] [overflow-wrap:anywhere]">
      <span className="sr-only">{leaked ? "leaked: " : `real ${CHIP_STYLES[type].label.toLowerCase()}: `}</span>
      <Glued icon={<Icon aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />} text={text} />
    </mark>
  );
}

/** Agent side: intel the security model will replace. */
export function IntelMark({ text }: { text: string }) {
  return (
    <mark className="rounded-sm bg-replaced/12 px-0.5 text-replaced underline decoration-replaced decoration-dashed decoration-2 underline-offset-[3px]">
      <span className="sr-only">intel: </span>
      <Glued icon={<ArrowLeftRight aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />} text={text} />
    </mark>
  );
}

/** Untrusted side: a neutral substitute for intel. Hover or focus shows why. */
export function ReplacedMark({ text, reason }: { text: string; reason?: string | null }) {
  return (
    <Tooltip>
      <TooltipTrigger
        type="button"
        className="cursor-help rounded-sm bg-replaced/12 px-0.5 font-mono text-replaced underline decoration-replaced decoration-dashed decoration-2 underline-offset-[3px]"
      >
        <span className="sr-only">intel replaced: </span>
        <Glued icon={<ArrowLeftRight aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />} text={text} />
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <span>
          <strong>Intel replaced.</strong> {reason ?? "A detail the endpoint could learn from was swapped for a neutral word."}
        </span>
      </TooltipContent>
    </Tooltip>
  );
}

export function RestoredMark({ text }: { text: string }) {
  return (
    <mark className="rounded-sm bg-restored/15 px-0.5 text-restored underline decoration-restored/70 decoration-2 underline-offset-[3px] [overflow-wrap:anywhere]">
      <span className="sr-only">restored locally: </span>
      <Glued icon={<RotateCcw aria-hidden className="mr-0.5 inline size-[0.85em] align-[-0.1em]" />} text={text} />
    </mark>
  );
}

export function HiddenBar({ summary }: { summary: string }) {
  return (
    <span className="my-1.5 flex items-start gap-2 rounded border border-dashed border-collapsed/60 bg-collapsed/10 px-2.5 py-1.5 whitespace-normal text-collapsed">
      <EyeOff aria-hidden className="mt-[0.25em] size-[1em] shrink-0" />
      <span>
        <span className="font-sans font-semibold">Intel hidden:</span> {summary}
      </span>
    </span>
  );
}

function Region({ tone, label, children }: { tone: "hidden" | "leak"; label: string; children: ReactNode }) {
  return (
    <span
      className={cn(
        "my-1.5 block border-l-2 border-dashed pl-3",
        tone === "hidden" ? "border-collapsed/70" : "border-leak/70",
      )}
    >
      <span className={cn("flex items-center gap-1.5 font-sans text-sm", tone === "hidden" ? "text-collapsed" : "text-leak")}>
        {tone === "hidden" ? <EyeOff aria-hidden className="size-3.5" /> : <TriangleAlert aria-hidden className="size-3.5" />}
        {label}
      </span>
      {children}
    </span>
  );
}

// ---------- segmentation ----------

type Inline =
  | { kind: "secret"; op: Op }
  | { kind: "intel"; op: Op }
  | { kind: "leak"; op: Op }
  | { kind: "restored"; op: Op }
  | { kind: "replaced"; op: Op }
  | { kind: "chip"; placeholder: string };

type InlineOpts = {
  index: ReplayIndex;
  /** Values to mark, and how. */
  values?: { op: Op; kind: "secret" | "intel" | "leak" | "restored" }[];
  /** Applied replace ops whose `with` text should be marked. */
  replaced?: Op[];
  chips?: boolean;
  modelPlaceholders?: Set<string>;
  flash?: Set<string>;
};

function renderInline(text: string, opts: InlineOpts, key: string): ReactNode[] {
  const matches: Match<Inline>[] = [
    ...findAll(
      text,
      (opts.values ?? []).map(({ op, kind }) => ({ needle: op.value ?? "", payload: { kind, op } as Inline })),
      { wordBoundary: true },
    ),
    ...findAll(
      text,
      (opts.replaced ?? []).map((op) => ({ needle: op.with ?? "", payload: { kind: "replaced", op } as Inline })),
    ),
    ...(opts.chips
      ? findRegex(text, PLACEHOLDER_RE).map((m) => ({ ...m, payload: { kind: "chip", placeholder: m.payload[0] } as Inline }))
      : []),
  ];
  const out: ReactNode[] = [];
  let cursor = 0;
  for (const m of nonOverlapping(matches)) {
    if (m.start > cursor) out.push(text.slice(cursor, m.start));
    const k = `${key}-${m.start}`;
    const value = text.slice(m.start, m.end);
    const p = m.payload;
    if (p.kind === "chip") {
      const info = placeholderInfo(opts.index, p.placeholder);
      out.push(
        <PlaceholderChip
          key={`${k}-${p.placeholder}`}
          placeholder={p.placeholder}
          type={info.type}
          alias={info.alias}
          model={opts.modelPlaceholders?.has(p.placeholder)}
          flash={opts.flash?.has(p.placeholder)}
        />,
      );
    } else if (p.kind === "replaced") out.push(<ReplacedMark key={k} text={value} reason={p.op.reason} />);
    else if (p.kind === "restored") out.push(<RestoredMark key={k} text={value} />);
    else if (p.kind === "intel") out.push(<IntelMark key={k} text={value} />);
    else out.push(<SecretMark key={k} text={value} type={chipType(p.op.type)} leaked={p.kind === "leak"} />);
    cursor = m.end;
  }
  if (cursor < text.length) out.push(text.slice(cursor));
  return out;
}

/** Split around block-level matches, dropping one newline on each side so blocks don't double-space. */
function splitBlocks<T>(text: string, matches: Match<T>[]) {
  const parts: ({ kind: "text"; text: string } | { kind: "block"; match: Match<T> })[] = [];
  let cursor = 0;
  for (const m of nonOverlapping(matches)) {
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

const applied = (ops: Op[], kind: Op["op"]) => ops.filter((o) => isApplied(o) && o.op === kind && o.value);

// ---------- public views ----------

/** Agent side: raw secrets in red, intel to be replaced in dashed amber, hidden line ranges outlined. */
export function RawText({ text, ops, index }: { text: string; ops: Op[]; index: ReplayIndex }) {
  const values = [
    ...applied(ops, "mask").map((op) => ({ op, kind: "secret" as const })),
    ...applied(ops, "replace").map((op) => ({ op, kind: "intel" as const })),
  ];
  const opts: InlineOpts = { index, values, chips: true };
  const hides = findAll(text, applied(ops, "hide").map((op) => ({ needle: op.value!, payload: op })));
  return (
    <p className={PRE}>
      {splitBlocks(text, hides).map((part, i) =>
        part.kind === "text" ? (
          renderInline(part.text, opts, `t${i}`)
        ) : (
          <Region key={`h${i}`} tone="hidden" label="Intel hidden before sending">
            {renderInline(text.slice(part.match.start, part.match.end), opts, `h${i}`)}
          </Region>
        ),
      )}
    </p>
  );
}

/** Untrusted side with MasqAI: chips, hidden bars, replaced intel; anything that slipped through in red. */
export function SanitizedText({
  text,
  ops,
  index,
  flash,
}: {
  text: string;
  ops: Op[];
  index: ReplayIndex;
  flash?: string[];
}) {
  const opts: InlineOpts = {
    index,
    chips: true,
    replaced: applied(ops, "replace"),
    // An applied mask whose raw value still appears verbatim reached upstream: show it as leaked.
    values: applied(ops, "mask").map((op) => ({ op, kind: "leak" as const })),
    modelPlaceholders: new Set(ops.filter((o) => isApplied(o) && o.source === "model" && o.placeholder).map((o) => o.placeholder!)),
    flash: new Set(flash ?? []),
  };
  return (
    <p className={PRE}>
      {splitBlocks(text, findRegex(text, HIDDEN_RE)).map((part, i) =>
        part.kind === "text" ? (
          renderInline(part.text, opts, `t${i}`)
        ) : (
          <HiddenBar key={`h${i}`} summary={part.match.payload[1]} />
        ),
      )}
    </p>
  );
}

/** Untrusted side without MasqAI: raw text, every op's value marked as leaked. */
export function LeakedText({ text, ops, index }: { text: string; ops: Op[]; index: ReplayIndex }) {
  const opts: InlineOpts = { index, values: index.leakable.map((op) => ({ op, kind: "leak" as const })) };
  const hides = findAll(text, applied(ops, "hide").map((op) => ({ needle: op.value!, payload: op })));
  return (
    <p className={PRE}>
      {splitBlocks(text, hides).map((part, i) =>
        part.kind === "text" ? (
          renderInline(part.text, opts, `t${i}`)
        ) : (
          <Region key={`h${i}`} tone="leak" label="Intel leaked (would have been hidden)">
            {renderInline(text.slice(part.match.start, part.match.end), opts, `h${i}`)}
          </Region>
        ),
      )}
    </p>
  );
}

/** Agent side of a tool call: values swapped back in from placeholders, in green. */
export function RestoredText({ text, index }: { text: string; index: ReplayIndex }) {
  const opts: InlineOpts = { index, chips: true, values: index.leakable.map((op) => ({ op, kind: "restored" as const })) };
  return <p className={PRE}>{renderInline(text, opts, "r")}</p>;
}
