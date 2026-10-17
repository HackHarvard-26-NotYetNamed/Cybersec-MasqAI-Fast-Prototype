"use client";

import {
  ArrowRight,
  CircleDashed,
  Copy,
  EyeOff,
  Link2,
  ListChecks,
  ScanSearch,
  Sparkles,
  Undo2,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import type { Op, Relink, Step } from "@/lib/data";
import { chipType, placeholderInfo, type ReplayIndex } from "@/lib/ops";
import { cn } from "@/lib/utils";
import { PlaceholderChip } from "./annotated-text";

type Decision = { label: string; hint: string; icon: LucideIcon; className: string; emphasis?: boolean };

/** Every source/verdict pair renders; the six the gateway emits get their own wording. */
export function decision(op: Op): Decision {
  const key = `${op.source}·${op.verdict}`;
  switch (key) {
    case "detector·applied":
      return { label: "detector · applied", hint: "caught by a rule", icon: ScanSearch, className: "border-border text-foreground" };
    case "auto·applied":
      return { label: "auto · applied", hint: "exact copy of a known value", icon: Copy, className: "border-border text-foreground" };
    case "auto·vetoed":
      return { label: "auto · vetoed", hint: "the security model undid it", icon: Undo2, className: "border-model/50 text-model" };
    case "auto·left_as_is":
      return { label: "auto · left as is", hint: "inside a longer word", icon: CircleDashed, className: "border-border text-muted-foreground" };
    case "model·applied":
      return { label: "model · applied", hint: "found by the security model", icon: Sparkles, className: "border-model bg-model/12 text-model", emphasis: true };
    case "model·rejected_invalid":
      return { label: "model · rejected (invalid)", hint: "failed validation, corrected in the retry round", icon: XCircle, className: "border-leak/50 text-leak" };
    default:
      return { label: `${op.source} · ${op.verdict.replace(/_/g, " ")}`, hint: "", icon: CircleDashed, className: "border-border text-muted-foreground" };
  }
}

const OP_LABEL: Record<Op["op"], string> = { mask: "Mask", hide: "Hide", replace: "Replace", relink: "Relink", unmask: "Unmask" };

function Result({ op, index }: { op: Op; index: ReplayIndex }) {
  const value = op.value ? <code className="font-mono break-all text-foreground">{truncate(op.value)}</code> : null;
  const arrow = <ArrowRight aria-label="becomes" className="inline size-3.5 shrink-0 text-muted-foreground" />;
  if (op.op === "hide")
    return (
      <p className="flex flex-wrap items-center gap-1.5">
        <EyeOff aria-hidden className="size-3.5 text-collapsed" />
        <span className="text-collapsed">{op.summary ?? "lines hidden"}</span>
      </p>
    );
  if (op.op === "replace")
    return (
      <p className="flex flex-wrap items-center gap-1.5">
        {value} {arrow}
        <span className="rounded-sm px-0.5 font-mono text-replaced underline decoration-replaced decoration-dashed decoration-2 underline-offset-[3px]">
          {op.with}
        </span>
      </p>
    );
  if (op.placeholder) {
    const info = placeholderInfo(index, op.placeholder);
    return (
      <p className="flex flex-wrap items-center gap-1.5">
        {value} {op.verdict === "applied" || op.op === "relink" ? arrow : null}
        {op.verdict === "applied" || op.op === "relink" ? (
          <PlaceholderChip placeholder={op.placeholder} type={chipType(op.type ?? info.type)} alias={op.alias || info.alias} />
        ) : (
          <span className="text-muted-foreground">kept as written</span>
        )}
      </p>
    );
  }
  return value ? <p>{value}</p> : null;
}

const truncate = (s: string) => (s.length > 90 ? s.slice(0, 60) + " … " + s.slice(-20) : s);

function OpRow({ op, index }: { op: Op; index: ReplayIndex }) {
  const d = decision(op);
  const Icon = d.icon;
  return (
    <li className={cn("rounded-md border bg-card p-3 text-sm", d.emphasis && "border-model/70 bg-model/8 shadow-sm")}>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-semibold">{OP_LABEL[op.op]}</span>
        <span
          className={cn(
            "rounded-full border px-1.5 text-xs font-medium",
            op.class === "intel" ? "border-replaced/60 text-replaced" : "border-leak/50 text-leak",
          )}
        >
          {op.class}
        </span>
        {op.type ? <span className="font-mono text-xs text-muted-foreground">{op.type}</span> : null}
        {op.alias ? <span className="font-mono text-xs text-muted-foreground">alias</span> : null}
      </div>
      <p className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap", d.className)}>
          <Icon aria-hidden className="size-3.5" />
          {d.label}
        </span>
        {d.hint ? <span className={cn("text-xs", d.emphasis ? "font-medium text-model" : "text-muted-foreground")}>{d.hint}</span> : null}
      </p>
      <div className="mt-2">
        <Result op={op} index={index} />
      </div>
      {op.reason ? <p className="mt-1.5 text-muted-foreground">{op.reason}</p> : null}
    </li>
  );
}

function RelinkRow({ relink, index }: { relink: Relink; index: ReplayIndex }) {
  return (
    <li className="rounded-md border border-model/70 bg-model/8 p-3 text-sm">
      <p className="flex items-center gap-1.5 font-semibold">
        <Link2 aria-hidden className="size-4 text-model" /> Relink
      </p>
      <p className="mt-2 flex flex-wrap items-center gap-1.5">
        <PlaceholderChip placeholder={relink.fromPlaceholder} type={placeholderInfo(index, relink.fromPlaceholder).type} />
        <ArrowRight aria-label="becomes" className="size-3.5 text-muted-foreground" />
        <PlaceholderChip placeholder={relink.toPlaceholder} type={placeholderInfo(index, relink.toPlaceholder).type} />
      </p>
      <p className="mt-1.5 text-muted-foreground">
        Rewrites step{relink.stepsRewritten.length === 1 ? "" : "s"} {relink.stepsRewritten.map((s) => s + 1).join(", ")}.
      </p>
      {relink.cacheBroken ? (
        <p className="mt-1.5 inline-flex rounded-md border border-replaced/60 px-2 py-0.5 text-xs font-medium text-replaced">
          Prompt cache broken: accepted for privacy
        </p>
      ) : null}
    </li>
  );
}

export function DecisionPanel({ step, stepNumber, index }: { step: Step; stepNumber: number; index: ReplayIndex }) {
  const modelCount = step.ops.filter((o) => o.source === "model" && o.verdict === "applied").length;
  return (
    <section aria-labelledby="decisions-title" className="flex h-full min-h-0 flex-col">
      <header className="border-b px-4 py-3">
        <h3 id="decisions-title" className="flex items-center gap-2 font-semibold">
          <ListChecks aria-hidden className="size-4" /> Decisions · step {stepNumber}
        </h3>
        <p className="text-sm text-muted-foreground">
          {step.ops.length} op{step.ops.length === 1 ? "" : "s"}
          {modelCount ? (
            <>
              {" · "}
              <span className="font-medium text-model">{modelCount} found by the security model</span>
            </>
          ) : null}
        </p>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto p-3" tabIndex={0} aria-label="Decisions for this step">
        {step.ops.length === 0 && step.relinks.length === 0 ? (
          <p className="p-1 text-sm text-muted-foreground">
            {step.blocked
              ? "No decisions: the request never got past inspection."
              : step.role === "assistant"
                ? "Model output. Only tool-call arguments are restored; nothing is masked on the way back."
                : "Nothing sensitive here: forwarded unchanged."}
          </p>
        ) : (
          <ul className="space-y-2">
            {step.relinks.map((r, i) => (
              <RelinkRow key={`r${i}`} relink={r} index={index} />
            ))}
            {step.ops.map((op, i) => (
              <OpRow key={i} op={op} index={index} />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
