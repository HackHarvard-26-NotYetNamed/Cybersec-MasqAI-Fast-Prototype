// Data contracts for the public site. Field names match what the gateway emits
// (GET /api/sessions/{id}/replay) and what the eval harness writes: do not rename them.
// Everything is validated here, so a malformed file shows a friendly error instead of crashing.
"use client";

import { useEffect, useState } from "react";
import { z } from "zod";

// ---------- replays ----------

export const OpSchema = z.object({
  op: z.enum(["mask", "hide", "replace", "relink", "unmask"]),
  class: z.enum(["secret", "intel"]),
  // Entity type, UPPER_SNAKE. PATH, KEY, EMAIL, HOST and USER get their own chip colors.
  type: z.string().nullable().optional(),
  placeholder: z.string().nullable().optional(),
  alias: z.boolean().optional().default(false),
  // The raw text the op acted on (for hide: the hidden lines).
  value: z.string().nullable().optional(),
  // replace: the neutral substitute.
  with: z.string().nullable().optional(),
  // hide: the one-line summary.
  summary: z.string().nullable().optional(),
  source: z.enum(["detector", "auto", "model"]),
  verdict: z.enum(["applied", "vetoed", "left_as_is", "rejected_invalid"]),
  reason: z.string().nullable().optional(),
});

export const RelinkSchema = z.object({
  fromPlaceholder: z.string(),
  toPlaceholder: z.string(),
  // 0-based indexes into `steps` whose sanitized text was rewritten.
  stepsRewritten: z.array(z.number().int().nonnegative()).default([]),
  cacheBroken: z.boolean().default(true),
});

export const BLOCK_REASONS = {
  security_model_failed: "Security model failed: fail closed",
  invalid_correction: "Security model answer invalid twice: fail closed",
  unknown_content_type: "Unrecognized content type: refused before inspection",
  unsupported_endpoint: "Unsupported endpoint: nothing forwarded",
  remote_security_model_refused: "Remote security model not allowed",
} as const;
export type BlockReason = keyof typeof BLOCK_REASONS;

export const BlockedSchema = z.object({
  reason: z.enum(Object.keys(BLOCK_REASONS) as [BlockReason, ...BlockReason[]]),
  status: z.union([z.literal(502), z.literal(422), z.literal(404)]),
});

export const ToolCallSchema = z.object({
  name: z.string(),
  argsSent: z.string(),
  argsRestored: z.string(),
});

export const StepSchema = z.object({
  t: z.number().nonnegative(),
  role: z.enum(["user", "assistant", "tool", "system"]),
  itemKind: z.string().nullable().optional(),
  raw: z.string(),
  sanitized: z.string(),
  ops: z.array(OpSchema).default([]),
  relinks: z.array(RelinkSchema).nullable().optional().transform((v) => v ?? []),
  toolCall: ToolCallSchema.nullable().optional(),
  blocked: BlockedSchema.nullable().optional().transform((v) => v ?? null),
});

export const ReplaySchema = z.object({
  id: z.string(),
  title: z.string(),
  summary: z.string(),
  relayRequestCount: z.number().int().nonnegative(),
  headersStripped: z.array(z.string()).default([]),
  pseudonymized: z.array(z.string()).default([]),
  steps: z.array(StepSchema).min(1),
});

export const ReplayIndexSchema = z
  .array(z.object({ id: z.string(), title: z.string(), file: z.string() }))
  .min(1);

export type Op = z.infer<typeof OpSchema>;
export type Relink = z.infer<typeof RelinkSchema>;
export type Blocked = z.infer<typeof BlockedSchema>;
export type ToolCall = z.infer<typeof ToolCallSchema>;
export type Step = z.infer<typeof StepSchema>;
export type Replay = z.infer<typeof ReplaySchema>;
export type ReplayIndex = z.infer<typeof ReplayIndexSchema>;

// ---------- results ----------

const rate = z.number().min(0).max(1);

export const MetricsSchema = z.object({
  leakRate: rate,
  taskSuccess: rate,
  avgTokens: z.number().nonnegative(),
  p50LatencyMs: z.number().nonnegative(),
});

export const ConditionSchema = z.object({
  id: z.string(),
  kind: z.enum(["raw", "masqai"]),
  label: z.string(),
  untrusted: z.string().optional(),
  security: z.object({ model: z.string().optional(), provider: z.string().optional(), think: z.boolean().optional() }).nullable().optional(),
});

export const ConditionMetricsSchema = MetricsSchema.extend({
  runs: z.number().int().nonnegative().optional(),
  blocked: z.number().int().nonnegative().optional(),
  expectedBlocks: z.number().int().nonnegative().optional(),
  toolCallsVetoed: z.number().int().nonnegative().optional(),
  examples: z.array(z.object({
    status: z.enum(["ok", "fail", "leak", "blocked"]),
    taskOk: z.boolean(),
    blocked: z.boolean(),
    leaked: z.boolean(),
    latencyMs: z.number().nonnegative().nullable().optional(),
    tokens: z.number().nonnegative(),
  })).optional(),
});

export const ResultsSchema = z.object({
  placeholder: z.boolean().optional().default(false),
  generatedAt: z.string(),
  runsPerCase: z.number().int().positive(),
  securityModel: z.string(),
  untrustedModel: z.string(),
  agent: z.string(),
  sandbox: z.string(),
  conditions: z.array(ConditionSchema).default([]),
  cases: z
    .array(z.object({
      id: z.string(),
      title: z.string(),
      raw: MetricsSchema.optional(),
      masqai: MetricsSchema.optional(),
      conditions: z.record(z.string(), ConditionMetricsSchema).default({}),
    }))
    .min(1),
  injection: z
    .array(
      z
        .object({ attack: z.string(), attempts: z.number().int().positive(), succeeded: z.number().int().nonnegative() })
        .refine((a) => a.succeeded <= a.attempts, { message: "succeeded cannot exceed attempts" }),
    )
    .default([]),
});

export type Metrics = z.infer<typeof MetricsSchema>;
export type Condition = z.infer<typeof ConditionSchema>;
export type ConditionMetrics = z.infer<typeof ConditionMetricsSchema>;
export type Results = z.infer<typeof ResultsSchema>;

// ---------- keys ----------

export const KeysSchema = z.object({
  status: z.enum(["planned", "live"]),
  provider: z.string(),
  keys: z.array(
    z.object({
      label: z.string(),
      createdAt: z.number().nonnegative(),
      activeUntil: z.number().nonnegative(),
      revokedAt: z.number().nonnegative(),
    }),
  ),
  honeytokens: z.array(
    z.object({
      label: z.string(),
      plantedAt: z.number().nonnegative(),
      usedAt: z.number().nonnegative().nullable(),
      usedBy: z.string().nullable(),
      verdict: z.string(),
    }),
  ),
});

export type Keys = z.infer<typeof KeysSchema>;

// ---------- media for /run-it ----------

export const MediaSchema = z.object({
  items: z.array(
    z.object({
      kind: z.enum(["image", "video"]),
      src: z.string(),
      alt: z.string(),
      caption: z.string().optional(),
    }),
  ),
});

export type Media = z.infer<typeof MediaSchema>;

// ---------- loading ----------

export type Loaded<T> =
  | { status: "loading" }
  | { status: "error"; url: string; message: string }
  | { status: "ok"; data: T };

export async function loadJson<T>(url: string, schema: z.ZodType<T>): Promise<Loaded<T>> {
  let body: unknown;
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return { status: "error", url, message: `HTTP ${res.status} while fetching the file.` };
    body = await res.json();
  } catch (err) {
    return { status: "error", url, message: `Could not read the file as JSON (${(err as Error).message}).` };
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) return { status: "error", url, message: z.prettifyError(parsed.error) };
  return { status: "ok", data: parsed.data };
}

export function useJson<T>(url: string | null, schema: z.ZodType<T>): Loaded<T> {
  const [state, setState] = useState<{ url: string | null; value: Loaded<T> }>({
    url: null,
    value: { status: "loading" },
  });
  useEffect(() => {
    if (!url) return;
    let live = true;
    loadJson(url, schema).then((value) => live && setState({ url, value }));
    return () => {
      live = false;
    };
  }, [url, schema]);
  return state.url === url ? state.value : { status: "loading" };
}
