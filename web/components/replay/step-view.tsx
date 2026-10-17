"use client";

import { ArrowLeft, ArrowRight, Ban, Bot, Link2, Settings2, SquareTerminal, UserRound, Wrench, type LucideIcon } from "lucide-react";
import type { Step } from "@/lib/data";
import { blockLabel, unprotectedText, type ReplayIndex } from "@/lib/ops";
import { cn } from "@/lib/utils";
import { LeakedText, RawText, RestoredText, SanitizedText } from "./annotated-text";

const ROLE: Record<Step["role"], { label: string; icon: LucideIcon }> = {
  system: { label: "System prompt", icon: Settings2 },
  user: { label: "Prompt", icon: UserRound },
  assistant: { label: "Model response", icon: Bot },
  tool: { label: "Tool output", icon: SquareTerminal },
};

export type PaneMode = "agent" | "untrusted" | "unprotected";

function StepHeader({ step, mode }: { step: Step; mode: PaneMode }) {
  const { label, icon: Icon } = ROLE[step.role];
  const inbound = step.role === "assistant";
  const Dir = inbound ? ArrowLeft : ArrowRight;
  const direction =
    mode === "agent"
      ? inbound
        ? "back from the untrusted model"
        : "leaves the agent"
      : inbound
        ? "untrusted model sends back"
        : "untrusted model receives";
  return (
    <div className="mb-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
      <span className="inline-flex items-center gap-1.5 font-medium text-foreground">
        <Icon aria-hidden className="size-4" />
        {label}
      </span>
      <span className="inline-flex items-center gap-1">
        <Dir aria-hidden className="size-3.5" />
        {direction}
      </span>
      <span className="ml-auto flex items-center gap-3">
        {step.itemKind ? <span className="font-mono">{step.itemKind}</span> : null}
        <span className="font-mono tabular-nums">+{step.t}s</span>
      </span>
    </div>
  );
}

function ToolCallBox({ step, mode, index }: { step: Step; mode: PaneMode; index: ReplayIndex }) {
  const call = step.toolCall;
  if (!call) return null;
  const restored = call.argsRestored !== call.argsSent;
  return (
    <div className={cn("mt-2 rounded-md border bg-background/60 p-3", mode === "agent" && restored && "border-restored/50")}>
      <div className="mb-1 flex flex-wrap items-center gap-2 text-sm">
        <Wrench aria-hidden className="size-4 text-muted-foreground" />
        <span className="font-medium">
          Tool call · <span className="font-mono">{call.name}</span>
        </span>
        {mode === "agent" ? (
          restored ? (
            <span className="ml-auto inline-flex items-center gap-1 rounded-full border border-restored/50 bg-restored/12 px-2 py-0.5 font-medium text-restored">
              <span aria-hidden>↺</span> restored locally
            </span>
          ) : (
            <span className="ml-auto text-muted-foreground">runs as sent</span>
          )
        ) : mode === "untrusted" ? (
          <span className="ml-auto text-muted-foreground">as the model wrote it</span>
        ) : null}
      </div>
      {mode === "agent" ? (
        <RestoredText text={call.argsRestored} index={index} />
      ) : mode === "untrusted" ? (
        <SanitizedText text={call.argsSent} ops={[]} index={index} />
      ) : (
        <LeakedText text={call.argsRestored} ops={[]} index={index} />
      )}
      {mode === "agent" && restored ? (
        <p className="mt-1 text-sm text-muted-foreground">
          Only tool-call arguments are restored. The model’s text is never modified.
        </p>
      ) : null}
    </div>
  );
}

export function StepView({
  step,
  stepIndex,
  mode,
  index,
  current,
  sanitized,
  rewrittenTo = [],
}: {
  step: Step;
  stepIndex: number;
  mode: PaneMode;
  index: ReplayIndex;
  current: boolean;
  /** The sanitized text as of the current step (relinks rewrite earlier steps). */
  sanitized?: string;
  rewrittenTo?: string[];
}) {
  return (
    <article
      data-step={stepIndex}
      aria-current={current ? "step" : undefined}
      className={cn(
        "rounded-lg border bg-card p-3 transition-colors sm:p-4",
        current ? "border-foreground/40 shadow-sm" : "border-border",
        rewrittenTo.length > 0 && "border-model/60",
      )}
    >
      <StepHeader step={step} mode={mode} />
      {mode === "untrusted" && rewrittenTo.length > 0 ? (
        <p className="mb-2 flex flex-wrap items-center gap-2 text-sm">
          <span className="inline-flex items-center gap-1.5 font-medium text-model">
            <Link2 aria-hidden className="size-4" /> Rewritten by a relink
          </span>
          <span className="rounded-md border border-replaced/60 px-2 py-0.5 text-xs font-medium text-replaced">
            Prompt cache broken: accepted for privacy
          </span>
        </p>
      ) : null}
      {mode === "agent" ? (
        <RawText text={step.raw} ops={step.ops} index={index} />
      ) : mode === "untrusted" ? (
        <SanitizedText text={sanitized ?? step.sanitized} ops={step.ops} index={index} flash={rewrittenTo} />
      ) : (
        <LeakedText text={unprotectedText(index, step)} ops={step.ops} index={index} />
      )}
      <ToolCallBox step={step} mode={mode} index={index} />
      {mode === "agent" && step.blocked ? (
        <p className="mt-2 inline-flex items-center gap-2 rounded-md border border-leak/50 bg-leak/10 px-2.5 py-1 text-sm font-medium text-leak">
          <Ban aria-hidden className="size-4" />
          {step.blocked.status} · {blockLabel(step.blocked.reason)} · not forwarded
        </p>
      ) : null}
    </article>
  );
}
