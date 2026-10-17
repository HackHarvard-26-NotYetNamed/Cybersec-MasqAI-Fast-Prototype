"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { Activity, Ban, CircleCheck, CircleDashed, CircleSlash, Loader2, PlugZap, ServerOff } from "lucide-react";
import { cn } from "@/lib/utils";

// Inlined at build time. Defaults to off; Vercel never sets it.
const LIVE_MODE = process.env.NEXT_PUBLIC_LIVE_MODE === "true";
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
// Same-origin paths, proxied to 127.0.0.1:8787 by the dev server only (see next.config.ts).
const BASE = "/gateway/api";

const noop = () => () => {};
function useHostname() {
  return useSyncExternalStore(noop, () => window.location.hostname, () => "");
}

export function LiveView() {
  const host = useHostname();
  if (!LIVE_MODE || (host && !LOOPBACK.has(host))) return <Explainer liveMode={LIVE_MODE} />;
  if (!host) return null;
  return <LiveGateway />;
}

function Explainer({ liveMode }: { liveMode: boolean }) {
  return (
    <div className="space-y-5">
      <div className="rounded-lg border bg-card p-5">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <ServerOff aria-hidden className="size-5" />
          This page only connects on your own machine
        </h2>
        <p className="mt-2 max-w-3xl text-pretty text-muted-foreground">
          The MasqAI gateway binds to <code className="font-mono text-foreground">127.0.0.1</code> and refuses
          cross-origin requests. That is the point: raw context never leaves the machine, so a public website can’t
          read it, and this one doesn’t try. {liveMode ? "Live mode is on, but this page is not being served from localhost." : "Live mode is off in this build."}
        </p>
      </div>
      <div className="rounded-lg border bg-card p-5">
        <h2 className="text-lg font-semibold">Run it locally</h2>
        <ol className="mt-3 list-decimal space-y-3 pl-5">
          <li>
            Start the gateway from the repository root:
            <pre className="mt-1 overflow-x-auto rounded-md bg-muted p-3 font-mono text-sm">python run_gateway.py</pre>
          </li>
          <li>
            Start this site in dev mode with live mode on:
            <pre className="mt-1 overflow-x-auto rounded-md bg-muted p-3 font-mono text-sm">
              cd web{"\n"}NEXT_PUBLIC_LIVE_MODE=true npm run dev
            </pre>
          </li>
          <li>
            Open <code className="font-mono">http://localhost:3000/live</code>. It shows request metadata only (status,
            stage, timing). For raw values, use the gateway’s own inspector at{" "}
            <code className="font-mono">http://127.0.0.1:8787</code>.
          </li>
        </ol>
      </div>
    </div>
  );
}

// ---------- defensive readers: the response shapes are not a contract ----------

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown, max = 80) =>
  typeof v === "string" ? (v.length > max ? v.slice(0, max) + "…" : v) : typeof v === "number" ? String(v) : "—";
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

type Fetched = { ok: true; body: unknown } | { ok: false; message: string };

async function fetchJson(path: string, retry = true): Promise<Fetched> {
  try {
    const res = await fetch(`${BASE}/${path}`, { cache: "no-store" });
    // The dev proxy can hit a keep-alive socket the gateway just closed (500); one retry covers it.
    if (res.status === 500 && retry) return fetchJson(path, false);
    if (res.status === 403) return { ok: false, message: "The gateway refused the request (403). Is the dev proxy in use?" };
    if (!res.ok) return { ok: false, message: `HTTP ${res.status}. Is the gateway running on 127.0.0.1:8787?` };
    const body: unknown = await res.json();
    console.info(`[live] /api/${path}`, body);
    return { ok: true, body };
  } catch (err) {
    if (retry) return fetchJson(path, false);
    return { ok: false, message: `Could not reach the gateway (${(err as Error).message}).` };
  }
}

type EventRow = { at: string; type: string; detail: string };

function LiveGateway() {
  const [state, setState] = useState<Fetched | null>(null);
  const [security, setSecurity] = useState<Fetched | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [stream, setStream] = useState<"connecting" | "open" | "closed">("connecting");

  useEffect(() => {
    let live = true;
    const poll = async () => {
      const [s, sec] = await Promise.all([fetchJson("state"), fetchJson("security")]);
      if (!live) return;
      setState(s);
      setSecurity(sec);
    };
    poll();
    // Under uvicorn's 5 s keep-alive, so the proxy rarely reuses a socket the gateway is closing.
    const id = setInterval(poll, 3000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    // /api/events is Server-Sent Events: `data: {json}` frames plus keepalive comments.
    const source = new EventSource(`${BASE}/events`);
    source.onopen = () => setStream("open");
    source.onerror = () => setStream(source.readyState === EventSource.CLOSED ? "closed" : "connecting");
    source.onmessage = (msg) => {
      let event: unknown;
      try {
        event = JSON.parse(msg.data);
      } catch {
        return;
      }
      console.info("[live] event", event);
      const e = isObj(event) ? event : {};
      const inner = isObj(e.trace) ? e.trace : isObj(e.session) ? e.session : {};
      const detail = isObj(e.trace)
        ? [text(inner.id, 24), text(inner.status, 16), text(inner.stage, 24)].join(" · ")
        : [text(inner.id, 32), `requests: ${text(inner.request_count, 6)}`].join(" · ");
      const type = text(e.type, 20);
      // A trace publishes on every progress tick; keep a row only when something visible changed.
      setEvents((prev) =>
        prev[0]?.type === type && prev[0]?.detail === detail
          ? prev
          : [{ at: new Date().toLocaleTimeString(), type, detail }, ...prev].slice(0, 40),
      );
    };
    return () => source.close();
  }, []);

  const stateBody = state?.ok && isObj(state.body) ? state.body : null;
  const traces = list(security?.ok && isObj(security.body) ? security.body.traces : stateBody?.traces).filter(isObj);
  const sessions = list(stateBody?.sessions);
  const error = state && !state.ok ? state.message : security && !security.ok ? security.message : null;

  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-3">
        <Stat label="Gateway" value={state === null ? "checking…" : error ? "unreachable" : "connected"} bad={!!error} />
        <Stat label="Sessions in RAM" value={stateBody ? String(sessions.length) : "—"} />
        <Stat label="Event stream" value={stream} bad={stream === "closed"} />
      </div>
      {error ? (
        <p role="alert" className="flex items-center gap-2 rounded-lg border border-leak/50 bg-leak/10 p-3 text-leak">
          <PlugZap aria-hidden className="size-4" />
          {error}
        </p>
      ) : null}

      <section className="rounded-lg border bg-card">
        <h2 className="flex items-center gap-2 border-b px-4 py-3 font-semibold">
          <Activity aria-hidden className="size-4" />
          Sanitize passes <span className="font-normal text-muted-foreground">(newest first, metadata only)</span>
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="text-muted-foreground">
              <tr className="border-b">
                {["Trace", "Status", "Stage", "Endpoint", "Duration", "Note"].map((h) => (
                  <th key={h} scope="col" className="px-4 py-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {traces.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-muted-foreground">
                    No traces yet. Send a request through the gateway.
                  </td>
                </tr>
              ) : (
                [...traces].reverse().slice(0, 30).map((t, i) => (
                  <tr key={text(t.id) + i} className="border-b last:border-0">
                    <td className="px-4 py-2 font-mono">{text(t.id, 24)}</td>
                    <td className="px-4 py-2">
                      <StatusChip status={text(t.status, 16)} />
                    </td>
                    <td className="px-4 py-2 font-mono">{text(t.stage, 24)}</td>
                    <td className="px-4 py-2 font-mono">{text(t.endpoint, 40)}</td>
                    <td className="px-4 py-2 font-mono tabular-nums">
                      {typeof t.duration_ms === "number" ? `${t.duration_ms} ms` : "—"}
                    </td>
                    {/* `reason` is a fixed gateway message; `error` can quote context, so it is never shown here. */}
                    <td className="px-4 py-2 text-muted-foreground">
                      {t.error ? "error details in the gateway inspector" : text(t.reason, 60)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-lg border bg-card">
        <h2 className="border-b px-4 py-3 font-semibold">Event stream</h2>
        <ol aria-live="polite" className="max-h-80 space-y-1 overflow-y-auto px-4 py-3 font-mono text-sm" tabIndex={0}>
          {events.length === 0 ? <li className="text-muted-foreground">Waiting for events…</li> : null}
          {events.map((e, i) => (
            <li key={events.length - i}>
              <span className="text-muted-foreground">{e.at}</span> {e.type} · {e.detail}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}

function Stat({ label, value, bad }: { label: string; value: string; bad?: boolean }) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className={cn("mt-1 font-mono text-xl font-semibold", bad && "text-leak")}>{value}</p>
    </div>
  );
}

function StatusChip({ status }: { status: string }) {
  const map: Record<string, { icon: typeof CircleCheck; className: string }> = {
    passed: { icon: CircleCheck, className: "text-foreground" },
    running: { icon: Loader2, className: "text-muted-foreground" },
    skipped: { icon: CircleDashed, className: "text-muted-foreground" },
    blocked: { icon: Ban, className: "text-leak" },
    error: { icon: CircleSlash, className: "text-leak" },
  };
  const { icon: Icon, className } = map[status] ?? { icon: CircleDashed, className: "text-muted-foreground" };
  return (
    <span className={cn("inline-flex items-center gap-1.5 font-medium", className)}>
      <Icon aria-hidden className={cn("size-4", status === "running" && "animate-spin")} />
      {status}
    </span>
  );
}
