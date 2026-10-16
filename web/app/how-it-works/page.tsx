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
  Cpu,
  DatabaseZap,
  EyeOff,
  Filter,
  Laptop,
  RadioTower,
  RotateCcw,
  ScanEye,
  ShieldCheck,
  ShieldQuestion,
  Shrink,
  type LucideIcon,
} from "lucide-react";
import { PageIntro } from "@/components/site/page-bits";

export const metadata: Metadata = {
  title: "How it works",
  description: "MasqAI's pipeline, trust model, and the trade-offs it makes.",
};

export default function HowItWorksPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-14 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="How it works" title="A firewall for context, on your machine">
        MasqAI listens on <code className="font-mono text-foreground">127.0.0.1:8787</code> and speaks the OpenAI and
        Anthropic wire formats, so an agent only needs a new base URL. Everything below happens before a byte leaves
        the machine.
      </PageIntro>

      <section aria-labelledby="pipeline-title" className="space-y-4">
        <h2 id="pipeline-title" className="text-2xl font-semibold">
          The pipeline
        </h2>
        <Pipeline />
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
              ["Gateway RAM", "The mapping table and raw values live only in process memory."],
              ["The local model", "And the policy prompts you configured for it."],
              ["The network link", "To the next hop: we assume no man-in-the-middle."],
            ]}
          />
          <TrustColumn
            icon={ShieldQuestion}
            tone="text-leak"
            title="Untrusted"
            items={[
              ["The filesystem", "Config, logs and caches at rest. Nothing sensitive is written to disk."],
              ["The upstream", "The provider or relay, and any gateways chained behind it."],
              ["Remote model output", "Treated as data. Only tool-call arguments are restored."],
            ]}
          />
          <TrustColumn
            icon={CircleSlash}
            tone="text-muted-foreground"
            title="Out of scope"
            items={[
              ["The agent’s own actions", "An agent that curls a secret it already holds is a permissions problem."],
              ["A compromised host", "Malware that can read process memory wins."],
              ["Network-level identity", "Your IP address and TLS fingerprint still reach the endpoint."],
            ]}
          />
        </div>
      </section>

      <section aria-labelledby="costs-title" className="space-y-4">
        <h2 id="costs-title" className="text-2xl font-semibold">
          What we give up
        </h2>
        <p className="max-w-3xl text-lg text-muted-foreground">
          A context firewall is a trade. These are the costs we accept, and the ones the evaluation measures.
        </p>
        <ul className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          <Cost icon={Shrink} title="Information loss from rephrasing">
            Collapsing tool output is lossy. If the security model prunes a line the task needed, the agent fails or
            asks again. Task success is tracked for exactly this reason.
          </Cost>
          <Cost icon={ScanEye} title="Imperfect detection">
            Regex can’t see names or phone numbers, and a 7B model misses things. MasqAI lowers exposure; it does not
            make it zero.
          </Cost>
          <Cost icon={EyeOff} title="Meaning still leaks">
            Placeholders hide values, not intent. The relay still learns what you are working on, the shape of your
            code, and every name that wasn’t flagged.
          </Cost>
          <Cost icon={DatabaseZap} title="Caching vs. privacy">
            When a later message reveals that an earlier fragment was a secret, MasqAI rewrites the earlier message.
            That breaks the prompt-cache prefix, which costs tokens and money.
          </Cost>
          <Cost icon={Cpu} title="Local compute cost">
            Every request runs through a local model. That adds latency and needs a machine that can run a 7B model
            alongside your work.
          </Cost>
        </ul>
      </section>

      <div className="flex flex-wrap gap-3">
        <Link
          href="/demo"
          className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85"
        >
          Watch it on six tasks <ArrowRight aria-hidden className="size-4" />
        </Link>
        <Link href="/results" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
          See the measured costs
        </Link>
      </div>
    </div>
  );
}

// ---------- pipeline diagram (CSS, no image) ----------

function Pipeline() {
  return (
    <figure
      aria-label="Pipeline: the agent's request passes header hygiene, detectors and the local security model on your machine, then goes to the relay. The model's tool calls come back through a local restore step."
      className="rounded-xl border bg-card p-4 sm:p-6"
    >
      <div className="flex flex-col items-stretch gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-[4] rounded-xl border-2 border-dashed border-restored/50 p-3 pt-8 sm:p-4 sm:pt-9">
          <p className="absolute top-2 left-3 flex items-center gap-1.5 text-sm font-medium text-restored">
            <Laptop aria-hidden className="size-4" /> Your machine · trusted RAM
          </p>
          <ol className="flex flex-col items-stretch gap-2 lg:flex-row lg:items-stretch">
            <Node icon={Laptop} title="Agent" text="Coding agent, chat client or tool. Points at 127.0.0.1:8787." />
            <Arrow />
            <Node icon={Filter} title="Header hygiene" text="Drops the client's keys and identifying headers." />
            <Arrow />
            <Node icon={Binary} title="Detectors" text="Regex + entropy: keys, JWTs, emails, PEM, host, user, paths." />
            <Arrow />
            <Node
              icon={BrainCircuit}
              title="Local LLM"
              text={
                <>
                  <span className="font-medium text-foreground">Mask</span> (reversible) or{" "}
                  <span className="font-medium text-foreground">collapse</span> (lossy).
                </>
              }
              accent
            />
          </ol>
        </div>
        <Arrow standalone />
        <div className="relative flex-1 rounded-xl border-2 border-dashed border-leak/50 p-3 pt-8 sm:p-4 sm:pt-9">
          <p className="absolute top-2 left-3 flex items-center gap-1.5 text-sm font-medium text-leak">
            <RadioTower aria-hidden className="size-4" /> Untrusted
          </p>
          <ol>
            <Node icon={RadioTower} title="Relay" text="Provider, reseller or relay. Sees placeholders only." />
          </ol>
        </div>
      </div>

      <div className="mt-4 grid gap-3 lg:grid-cols-[4fr_1fr]">
        <p className="flex items-start gap-3 rounded-lg border border-restored/50 bg-restored/8 p-3">
          <span className="mt-0.5 flex shrink-0 items-center text-restored">
            <ArrowLeft aria-hidden className="size-4" />
            <RotateCcw aria-hidden className="size-4" />
          </span>
          <span>
            <strong className="font-semibold text-restored">Restore path.</strong> The response comes back through
            the gateway. Placeholders inside tool-call arguments become real values again, so commands run on real
            paths. Chat text is not restored.
          </span>
        </p>
        <p className="flex items-start gap-3 rounded-lg border border-leak/50 bg-leak/8 p-3">
          <Ban aria-hidden className="mt-0.5 size-4 shrink-0 text-leak" />
          <span>
            <strong className="font-semibold text-leak">Fail closed.</strong> Model down or invalid output: HTTP 502,
            nothing sent.
          </span>
        </p>
      </div>
    </figure>
  );
}

function Node({
  icon: Icon,
  title,
  text,
  accent,
}: {
  icon: LucideIcon;
  title: string;
  text: React.ReactNode;
  accent?: boolean;
}) {
  return (
    <li className={`flex-1 list-none rounded-lg border bg-background p-3 ${accent ? "border-restored/60" : ""}`}>
      <p className="flex items-center gap-2 font-semibold">
        <Icon aria-hidden className="size-4 shrink-0" />
        {title}
      </p>
      <p className="mt-1 text-sm text-muted-foreground">{text}</p>
    </li>
  );
}

function Arrow({ standalone }: { standalone?: boolean }) {
  const Tag = standalone ? "div" : "li";
  return (
    <Tag aria-hidden className="flex list-none items-center justify-center text-muted-foreground">
      <ArrowDown className="size-5 lg:hidden" />
      <ArrowRight className="hidden size-5 lg:block" />
    </Tag>
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

function Cost({ icon: Icon, title, children }: { icon: LucideIcon; title: string; children: React.ReactNode }) {
  return (
    <li className="rounded-lg border bg-card p-4">
      <p className="flex items-center gap-2 font-semibold">
        <Icon aria-hidden className="size-5 text-ent-key" />
        {title}
      </p>
      <p className="mt-2 text-pretty text-muted-foreground">{children}</p>
    </li>
  );
}
