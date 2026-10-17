import Link from "next/link";
import {
  ArrowRight,
  Ban,
  Binary,
  BrainCircuit,
  Copy,
  Fingerprint,
  FolderTree,
  KeyRound,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  Telescope,
  UserRound,
} from "lucide-react";
import { MirrorHero } from "@/components/landing/mirror";

export default function Home() {
  return (
    <>
      <section className="bg-grid border-b">
        <div className="mx-auto max-w-7xl px-4 pt-12 pb-14 sm:px-6 sm:pt-16">
          <p className="font-mono text-sm tracking-wide text-muted-foreground uppercase">
            Local context firewall for AI agents
          </p>
          <h1 className="mt-3 max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
            Your LLM key is a two-way mirror. <span className="text-restored">MasqAI makes it one-way.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-lg text-pretty text-muted-foreground">
            MasqAI runs on your own machine. A trusted security model inspects every request inline, before anything
            reaches the untrusted model: secrets are masked, intel is hidden or replaced, and real values are swapped
            back in locally when a tool call needs them.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link
              href="/demo"
              className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85"
            >
              Watch the replays <ArrowRight aria-hidden className="size-4" />
            </Link>
            <Link
              href="/results"
              className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent"
            >
              See the numbers
            </Link>
          </div>
          <div className="mt-10">
            <MirrorHero />
          </div>
        </div>
      </section>

      <section aria-labelledby="origin" className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
        <div className="grid gap-8 lg:grid-cols-[1fr_1.2fr]">
          <div>
            <p className="font-mono text-sm tracking-wide text-muted-foreground uppercase">Why this exists</p>
            <h2 id="origin" className="mt-2 text-3xl font-semibold tracking-tight text-balance">
              Our own key leaked. We saw what an endpoint operator can see.
            </h2>
          </div>
          <div className="space-y-4 text-lg text-pretty text-muted-foreground">
            <p>
              People treat an API key as a billing token. It is really a channel: whoever operates the endpoint
              behind it reads everything sent through it. Coding agents send a lot, and most of it is not code.
            </p>
            <ul className="space-y-3 text-foreground">
              <li className="flex gap-3">
                <Fingerprint aria-hidden className="mt-1 size-5 shrink-0 text-ent-host" />
                <span>
                  <strong className="font-semibold">Machine fingerprints</strong>: OS, hardware and host names, pasted
                  in from diagnostic commands.
                </span>
              </li>
              <li className="flex gap-3">
                <FolderTree aria-hidden className="mt-1 size-5 shrink-0 text-ent-path" />
                <span>
                  <strong className="font-semibold">Internal details</strong>: the filesystem path to a production
                  database, internal host names, keys in config files.
                </span>
              </li>
              <li className="flex gap-3">
                <UserRound aria-hidden className="mt-1 size-5 shrink-0 text-ent-user" />
                <span>
                  <strong className="font-semibold">Personal identities</strong>: usernames, emails and chat handles
                  from git history and configs.
                </span>
              </li>
            </ul>
            <p className="text-base">
              We publish no third-party data. Every value on this site comes from our synthetic playground.
            </p>
          </div>
        </div>
      </section>

      <section aria-labelledby="secret-intel" className="border-t bg-card/50">
        <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
          <h2 id="secret-intel" className="text-3xl font-semibold tracking-tight">
            Secret vs. intel
          </h2>
          <p className="mt-2 max-w-3xl text-lg text-muted-foreground">
            Ordinary data-loss tools catch secrets. MasqAI also stops intel.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <Kind
              icon={<KeyRound aria-hidden className="size-5 text-leak" />}
              title="Secret"
              definition="A concrete string that unlocks or identifies something."
              handling="Masked: reversible, restored in tool calls."
              examples={[
                ["sk-or-v1-FAKEFAKE5e2b…", "an API key"],
                ["C:\\Users\\alice\\…\\prod\\inventory.db", "a path to private data"],
                ["DESKTOP-7Q2XK9M", "a device name"],
              ]}
            />
            <Kind
              icon={<Telescope aria-hidden className="size-5 text-replaced" />}
              title="Intel"
              definition="Something the endpoint could conclude about you."
              handling="Hidden or replaced: lossy, never restored."
              examples={[
                ["“a short walk from Davis Square”", "where someone lives"],
                ["an env dump with every drive and tool", "the shape of your machine"],
                ["the agenda of an unreleased design doc", "what your team is building"],
              ]}
            />
          </div>
        </div>
      </section>

      <section aria-labelledby="threats" className="border-y bg-card/50">
        <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
          <h2 id="threats" className="text-3xl font-semibold tracking-tight">
            Two assets, two threats
          </h2>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <ThreatCard
              icon={<KeyRound aria-hidden className="size-6 text-ent-key" />}
              asset="The key"
              threat="Whoever obtains it: a leak, a shared team key, a borrowed key."
              defense="Key Enigma"
              defenseText="Rotates the upstream key continuously, so a leaked key dies within minutes. Canary keys catch a relay that reuses your traffic."
              status="Stretch goal: planned"
              href="/trust"
            />
            <ThreatCard
              icon={<ScanSearch aria-hidden className="size-6 text-ent-path" />}
              asset="The context"
              threat="Whoever operates the endpoint: a provider, a cheap reseller, a relay, an opaque agent app."
              defense="The sanitizer"
              defenseText="Detectors and a local security model mask secrets and hide or replace intel before anything reaches the untrusted model, then restore real values in tool calls."
              status="Prototype works; rebuild in progress"
              href="/how-it-works"
            />
          </div>
        </div>
      </section>

      <section aria-labelledby="pipeline" className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
        <h2 id="pipeline" className="text-3xl font-semibold tracking-tight">
          Every request, inspected before it leaves
        </h2>
        <ol className="mt-8 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Step n={1} icon={<Binary aria-hidden className="size-5" />} title="Detectors">
            Rule tables for keys, PEM blocks, emails, cloud tokens, passwords and host identifiers. Fast, can’t be
            prompt-injected, and they only ever mask.
          </Step>
          <Step n={2} icon={<Copy aria-hidden className="size-5" />} title="Auto masks">
            Every exact copy of a known value is masked too, but never inside a longer word: with username{" "}
            <code className="font-mono">andy</code>, “handy” is left for the security model to judge.
          </Step>
          <Step n={3} icon={<BrainCircuit aria-hidden className="size-5" />} title="Security model">
            Adds the masks the rules missed, vetoes wrong auto masks, links partial forms, and hides or replaces intel in
            tool results.
          </Step>
          <Step n={4} icon={<RotateCcw aria-hidden className="size-5" />} title="Restore">
            In tool-call arguments only, placeholders become real values again, locally. The untrusted model’s text is
            never modified.
          </Step>
        </ol>
        <p className="mt-6 flex items-start gap-3 rounded-lg border border-leak/40 bg-leak/6 p-4 text-pretty">
          <Ban aria-hidden className="mt-0.5 size-5 shrink-0 text-leak" />
          <span>
            <strong className="font-semibold">Fails closed.</strong> Security model down or answering nonsense: 502.
            Content it can’t inspect: 422. Unsupported endpoint: 404. Nothing is ever sent raw.
          </span>
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link
            href="/demo"
            className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85"
          >
            See it on eight tasks <ArrowRight aria-hidden className="size-4" />
          </Link>
          <Link
            href="/results"
            className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent"
          >
            See the numbers
          </Link>
        </div>
      </section>
    </>
  );
}

function ThreatCard({
  icon,
  asset,
  threat,
  defense,
  defenseText,
  status,
  href,
}: {
  icon: React.ReactNode;
  asset: string;
  threat: string;
  defense: string;
  defenseText: string;
  status: string;
  href: string;
}) {
  return (
    <article className="flex flex-col rounded-xl border bg-card p-6">
      <div className="flex items-center gap-3">
        {icon}
        <h3 className="text-xl font-semibold">{asset}</h3>
      </div>
      <p className="mt-4 text-sm font-medium text-muted-foreground uppercase">Threat</p>
      <p className="mt-1 text-lg">{threat}</p>
      <p className="mt-4 flex flex-wrap items-center gap-2 text-sm font-medium text-muted-foreground uppercase">
        Defense
        <span className="rounded-full border px-2 py-0.5 font-mono text-xs normal-case">{status}</span>
      </p>
      <p className="mt-1 flex items-center gap-2 text-lg font-semibold">
        <ShieldCheck aria-hidden className="size-5 text-restored" />
        {defense}
      </p>
      <p className="mt-1 flex-1 text-muted-foreground">{defenseText}</p>
      <Link href={href} className="mt-4 inline-flex items-center gap-1 font-medium underline-offset-4 hover:underline">
        More on {defense.replace(/^The /, "the ")} <ArrowRight aria-hidden className="size-4" />
      </Link>
    </article>
  );
}

function Kind({
  icon,
  title,
  definition,
  handling,
  examples,
}: {
  icon: React.ReactNode;
  title: string;
  definition: string;
  handling: string;
  examples: [string, string][];
}) {
  return (
    <article className="rounded-xl border bg-card p-6">
      <h3 className="flex items-center gap-3 text-xl font-semibold">
        {icon}
        {title}
      </h3>
      <p className="mt-2 text-lg">{definition}</p>
      <p className="mt-1 text-muted-foreground">{handling}</p>
      <ul className="mt-4 space-y-2">
        {examples.map(([example, meaning]) => (
          <li key={example} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 rounded-md border bg-background px-3 py-2">
            <code className="font-mono text-[15px] break-all">{example}</code>
            <span className="text-sm text-muted-foreground">{meaning}</span>
          </li>
        ))}
      </ul>
    </article>
  );
}

function Step({ n, icon, title, children }: { n: number; icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <li className="rounded-xl border bg-card p-5">
      <p className="flex items-center gap-2 font-semibold">
        <span className="grid size-7 place-items-center rounded-full border font-mono text-sm">{n}</span>
        {icon}
        {title}
      </p>
      <p className="mt-3 text-pretty text-muted-foreground">{children}</p>
    </li>
  );
}
