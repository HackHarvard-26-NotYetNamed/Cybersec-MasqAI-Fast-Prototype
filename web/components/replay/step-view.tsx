import { ArrowLeft, ArrowRight, Ban, Bot, SquareTerminal, UserRound, Wrench, type LucideIcon } from "lucide-react";
import type { Step } from "@/lib/data";
import { unprotectedText, type ReplayIndex } from "@/lib/entities";
import { cn } from "@/lib/utils";
import { LeakedText, RawText, RestoredText, SanitizedText } from "./annotated-text";

const ROLE: Record<Step["role"], { label: string; icon: LucideIcon }> = {
  user: { label: "Prompt", icon: UserRound },
  assistant: { label: "Model response", icon: Bot },
  tool: { label: "Tool output", icon: SquareTerminal },
};

export type PaneMode = "agent" | "relay" | "unprotected";

function StepHeader({ step, mode }: { step: Step; mode: PaneMode }) {
  const { label, icon: Icon } = ROLE[step.role];
  const inbound = step.role === "assistant";
  const Dir = inbound ? ArrowLeft : ArrowRight;
  const direction =
    mode === "agent" ? (inbound ? "received from relay" : "leaves the agent") : inbound ? "relay sends back" : "relay receives";
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
      <span className="ml-auto font-mono tabular-nums">+{step.t}s</span>
    </div>
  );
}

function ToolCallBox({ step, mode, index }: { step: Step; mode: PaneMode; index: ReplayIndex }) {
  const call = step.toolCall;
  if (!call) return null;
  const restored = call.argsRestored !== call.argsSent;
  return (
    <div
      className={cn(
        "mt-2 rounded-md border bg-background/60 p-3",
        mode === "agent" && restored && "border-restored/50",
      )}
    >
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
        ) : mode === "relay" ? (
          <span className="ml-auto text-muted-foreground">model wrote</span>
        ) : null}
      </div>
      {mode === "agent" ? (
        <RestoredText text={call.argsRestored} index={index} />
      ) : mode === "relay" ? (
        <SanitizedText text={call.argsSent} entities={[]} index={index} />
      ) : (
        <LeakedText text={call.argsRestored} index={index} />
      )}
    </div>
  );
}

export function StepView({
  step,
  mode,
  index,
  current,
}: {
  step: Step;
  mode: PaneMode;
  index: ReplayIndex;
  current: boolean;
}) {
  return (
    <article
      aria-current={current ? "step" : undefined}
      className={cn(
        "rounded-lg border bg-card p-3 transition-colors sm:p-4",
        current ? "border-foreground/40 shadow-sm" : "border-border",
      )}
    >
      <StepHeader step={step} mode={mode} />
      {mode === "agent" ? (
        <RawText text={step.raw} entities={step.entities} index={index} />
      ) : mode === "relay" ? (
        <SanitizedText text={step.sanitized} entities={step.entities} index={index} />
      ) : (
        <LeakedText text={unprotectedText(index, step)} index={index} />
      )}
      <ToolCallBox step={step} mode={mode} index={index} />
      {mode === "agent" && step.blocked ? (
        <p className="mt-2 inline-flex items-center gap-2 rounded-md border border-leak/50 bg-leak/10 px-2.5 py-1 text-sm font-medium text-leak">
          <Ban aria-hidden className="size-4" />
          HTTP 502 masqai_sanitization_error · not forwarded
        </p>
      ) : null}
    </article>
  );
}
