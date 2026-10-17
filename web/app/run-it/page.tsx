import type { Metadata } from "next";
import { Ban, Database, KeyRound, ListChecks, Settings2, ShieldAlert, SplitSquareHorizontal } from "lucide-react";
import { PageIntro } from "@/components/site/page-bits";
import { GuiMedia } from "@/components/run-it/gui-media";

export const metadata: Metadata = {
  title: "Run it",
  description: "Start the MasqAI gateway on your own machine and use its built-in GUI.",
};

export default function RunItPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-10 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="Run it" title="The live view lives on your machine">
        This site only replays synthetic sessions. To watch real traffic, run the gateway yourself and open its
        built-in GUI.
      </PageIntro>

      <section aria-labelledby="why" className="rounded-xl border bg-card p-5">
        <h2 id="why" className="flex items-center gap-2 text-lg font-semibold">
          <Ban aria-hidden className="size-5 text-leak" />
          Why this site can’t show your gateway
        </h2>
        <p className="mt-2 max-w-3xl text-pretty text-muted-foreground">
          The gateway refuses browser requests from any other origin (it checks{" "}
          <code className="font-mono text-foreground">Sec-Fetch-Site</code>) and every control call needs an admin
          token generated at startup. A page served from anywhere else, even{" "}
          <code className="font-mono text-foreground">localhost:3000</code>, cannot read it, and must not: the gateway
          holds your raw context in RAM. That is the point.
        </p>
      </section>

      <section aria-labelledby="start" className="space-y-4">
        <h2 id="start" className="text-2xl font-semibold">
          Start the gateway
        </h2>
        <ol className="grid gap-4 lg:grid-cols-2">
          <StepCard n={1} title="Pull the security model">
            <p>The default security model runs locally in Ollama.</p>
            <Code>ollama pull qwen2.5:7b</Code>
          </StepCard>
          <StepCard n={2} title="Give the gateway your provider key, by env var">
            <p>
              <code className="font-mono">masqai.json</code> names the env var; the key itself never goes in a file.
            </p>
            <Code>{`export OPENROUTER_API_KEY=sk-or-v1-...      # macOS / Linux\n$env:OPENROUTER_API_KEY = "sk-or-v1-..."   # PowerShell`}</Code>
          </StepCard>
          <StepCard n={3} title="Run it and open the printed URL">
            <p>From the repository root. The admin token is printed once, and changes on every start.</p>
            <Code>{`python run_gateway.py\n\n  GUI: http://127.0.0.1:8787/#token=…\n  MASQAI_ADMIN_TOKEN=…`}</Code>
            <p className="text-sm text-muted-foreground">
              The GUI moves the token out of the URL into session storage. Don’t paste it anywhere else.
            </p>
          </StepCard>
          <StepCard n={4} title="Point your agent at it">
            <p>Use the gateway as the agent’s OpenAI- or Anthropic-compatible base URL. OpenCode is supported first.</p>
            <Code>http://127.0.0.1:8787/v1</Code>
          </StepCard>
        </ol>
      </section>

      <section aria-labelledby="gui" className="space-y-4">
        <h2 id="gui" className="text-2xl font-semibold">
          The built-in GUI
        </h2>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Tab icon={SplitSquareHorizontal} title="Context">
            The dual-reality inspector: raw and sanitized side by side, per item.
          </Tab>
          <Tab icon={ShieldAlert} title="Security">
            Every security-model call: its input, raw answer, each op ✓/✗, and why a request was blocked.
          </Tab>
          <Tab icon={Database} title="Mapping">
            The entity table: token, type, class, origin, links. Forget a session from here.
          </Tab>
          <Tab icon={Settings2} title="Config">
            Live config with inline validation, the security prompt, and the remote-model switch.
          </Tab>
        </ul>
        <GuiMedia />
        <p className="flex items-start gap-2 text-sm text-muted-foreground">
          <KeyRound aria-hidden className="mt-0.5 size-4 shrink-0" />
          The GUI shows raw values to you, the local user. Use a demo account or the playground before sharing your
          screen.
        </p>
      </section>

      <p className="flex items-start gap-2 text-muted-foreground">
        <ListChecks aria-hidden className="mt-1 size-4 shrink-0" />
        <span>
          Want a replay like the ones on this site? Start the gateway with <code className="font-mono">--playground</code>{" "}
          and export a session; the README in <code className="font-mono">web/</code> has the command.
        </span>
      </p>
    </div>
  );
}

function StepCard({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <li className="space-y-2 rounded-xl border bg-card p-5">
      <h3 className="flex items-center gap-2 font-semibold">
        <span className="grid size-7 place-items-center rounded-full border font-mono text-sm">{n}</span>
        {title}
      </h3>
      {children}
    </li>
  );
}

function Code({ children }: { children: string }) {
  return <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-sm">{children}</pre>;
}

function Tab({ icon: Icon, title, children }: { icon: typeof Ban; title: string; children: React.ReactNode }) {
  return (
    <li className="rounded-lg border bg-card p-4">
      <p className="flex items-center gap-2 font-semibold">
        <Icon aria-hidden className="size-4" />
        {title}
      </p>
      <p className="mt-1 text-sm text-muted-foreground">{children}</p>
    </li>
  );
}
