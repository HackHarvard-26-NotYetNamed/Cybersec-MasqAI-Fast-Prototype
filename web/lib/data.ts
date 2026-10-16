// Data contracts for the public site. Everything rendered comes from static JSON in /public/data/,
// validated here, so a malformed file shows a friendly error instead of crashing the page.
"use client";

import { useEffect, useState } from "react";
import { z } from "zod";

// ---------- replays ----------

export const ENTITY_TYPES = ["PATH", "KEY", "EMAIL", "HOST", "USER"] as const;
export type KnownEntityType = (typeof ENTITY_TYPES)[number];

export const EntitySchema = z.object({
  // Known types get a dedicated chip color; anything else renders as a neutral "OTHER" chip.
  type: z.string().min(1),
  // For mask/partial: the placeholder in `sanitized`. For collapse: the full MASQ_BLOCK marker.
  placeholder: z.string().min(1),
  // The real value (or, for collapse, the original block). Synthetic in every shipped file.
  value: z.string().min(1),
  op: z.enum(["mask", "partial", "collapse"]),
  // The security model missed it: the value went upstream verbatim. Counted as exposed.
  missed: z.boolean().optional().default(false),
});

export const ToolCallSchema = z.object({
  name: z.string(),
  argsSent: z.string(),
  argsRestored: z.string(),
});

export const StepSchema = z.object({
  t: z.number().nonnegative(),
  role: z.enum(["user", "assistant", "tool"]),
  raw: z.string(),
  sanitized: z.string(),
  entities: z.array(EntitySchema).default([]),
  toolCall: ToolCallSchema.nullable().optional(),
  blocked: z.boolean().default(false),
  // Optional narration shown above the step (e.g. "Ollama stopped").
  note: z.string().optional(),
});

export const ReplaySchema = z.object({
  id: z.string(),
  title: z.string(),
  summary: z.string(),
  relayRequestCount: z.number().int().nonnegative(),
  steps: z.array(StepSchema).min(1),
});

export const ReplayIndexSchema = z.object({
  replays: z.array(z.object({ id: z.string(), title: z.string(), file: z.string() })).min(1),
});

export type Entity = z.infer<typeof EntitySchema>;
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

export const ResultsSchema = z.object({
  generatedAt: z.string(),
  placeholder: z.boolean().optional().default(false),
  runsPerCase: z.number().int().positive(),
  model: z.string(),
  agent: z.string(),
  sandbox: z.string(),
  cases: z
    .array(z.object({ id: z.string(), title: z.string(), raw: MetricsSchema, masqai: MetricsSchema }))
    .min(1),
});

export type Metrics = z.infer<typeof MetricsSchema>;
export type Results = z.infer<typeof ResultsSchema>;

// ---------- keys ----------

export const KeysSchema = z.object({
  provider: z.string(),
  placeholder: z.boolean().optional().default(false),
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
