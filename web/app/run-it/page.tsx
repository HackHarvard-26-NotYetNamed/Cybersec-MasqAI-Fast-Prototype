import type { Metadata } from "next";
import { Ban, Database, Download, KeyRound, Play, Plug, Settings2, ShieldAlert, SplitSquareHorizontal, type LucideIcon } from "lucide-react";
import { GuiMedia } from "@/components/run-it/gui-media";

export const metadata: Metadata = {
  title: "Run it",
  description: "Start the MasqAI gateway on your own machine and use its built-in GUI.",
};

export default function RunItPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-10 px-4 py-8 sm:px-6 sm:py-10">
      <div className="space-y-3">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Run it on your machine</h1>
        <p className="inline-flex items-center gap-2 rounded-full border border-leak/40 bg-leak/6 px-3 py-1 text-sm">
          <Ban aria-hidden className="size-4 text-leak" />
          No website can read your gateway: it answers only its own page, with a token made at each start.
        </p>
      </div>

      <section aria-labelledby="gui" className="space-y-4">
        <h2 id="gui" className="sr-only">The built-in GUI</h2>
        <GuiMedia />
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tab icon={SplitSquareHorizontal} title="Context" sub="raw vs. sent, side by side" />
          <Tab icon={ShieldAlert} title="Security" sub="every model call, ✓ or ✗" />
          <Tab icon={Database} title="Mapping" sub="placeholder → real value" />
          <Tab icon={Settings2} title="Settings" sub="what to protect, live" />
        </ul>
      </section>

      <section aria-labelledby="start" className="space-y-4">
        <h2 id="start" className="text-2xl font-semibold">Four steps</h2>
        <ol className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Step n={1} icon={Download} title="Get the security model" code="ollama pull qwen2.5:7b" />
          <Step n={2} icon={KeyRound} title="Key by env var, never a file" code="export OPENROUTER_API_KEY=…" />
          <Step n={3} icon={Play} title="Start it, open the printed URL" code={"python run_gateway.py\n→ 127.0.0.1:8787/#token=…"} />
          <Step n={4} icon={Plug} title="Point your agent at it" code="http://127.0.0.1:8787/v1" />
        </ol>
      </section>
    </div>
  );
}

function Step({ n, icon: Icon, title, code }: { n: number; icon: LucideIcon; title: string; code: string }) {
  return (
    <li className="flex flex-col gap-3 rounded-xl border bg-card p-4">
      <p className="flex items-center gap-2 font-semibold">
        <span className="grid size-7 shrink-0 place-items-center rounded-full border font-mono text-sm">{n}</span>
        <Icon aria-hidden className="size-4 shrink-0 text-restored" />
        {title}
      </p>
      <pre className="mt-auto overflow-x-auto rounded-md bg-muted p-3 font-mono text-sm">{code}</pre>
    </li>
  );
}

function Tab({ icon: Icon, title, sub }: { icon: LucideIcon; title: string; sub: string }) {
  return (
    <li className="flex items-center gap-3 rounded-lg border bg-card p-3">
      <Icon aria-hidden className="size-5 shrink-0 text-restored" />
      <span>
        <span className="block font-semibold">{title}</span>
        <span className="text-sm text-muted-foreground">{sub}</span>
      </span>
    </li>
  );
}
