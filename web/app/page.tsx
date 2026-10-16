import Link from "next/link";
import {
  ArrowRight,
  Ban,
  Binary,
  BrainCircuit,
  Fingerprint,
  FolderTree,
  KeyRound,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import { MirrorHero } from "@/components/landing/mirror";

export default function Home() {
  return (
    <>
      <section className="bg-grid border-b">
        <div className="mx-auto max-w-7xl px-4 pt-12 pb-14 sm:px-6 sm:pt-16">
          <p className="font-mono text-sm tracking-wide text-muted-foreground uppercase">
            Local context firewall for AI coding agents
          </p>
          <h1 className="mt-3 max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
            Your LLM key is a two-way mirror. <span className="text-restored">MasqAI makes it one-way.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-lg text-pretty text-muted-foreground">
            MasqAI runs on your own machine, between your agent and an LLM endpoint you don’t trust. Secrets are
            masked before they leave, and swapped back in locally when the model asks to use them.
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
              defenseText="Rotates the upstream key continuously, so a leaked key dies within minutes. Planted canary keys catch relays that reuse traffic."
              status="Planned this weekend"
              href="/trust"
            />
            <ThreatCard
              icon={<ScanSearch aria-hidden className="size-6 text-ent-path" />}
              asset="The context"
              threat="Whoever operates the endpoint: the provider, a reseller, a relay."
              defense="Sanitizer"
              defenseText="Masks secrets and collapses noisy tool output on your machine before anything goes upstream, then restores real values in tool calls."
              status="Working prototype"
              href="/how-it-works"
            />
          </div>
        </div>
      </section>

      <section aria-labelledby="pipeline" className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
        <h2 id="pipeline" className="text-3xl font-semibold tracking-tight">
          Every request, three steps
        </h2>
        <ol className="mt-8 grid gap-4 md:grid-cols-3">
          <Step n={1} icon={<Binary aria-hidden className="size-5" />} title="Detectors">
            Regex and entropy checks for API keys, JWTs, emails, PEM blocks, host names, usernames and home paths.
          </Step>
          <Step n={2} icon={<BrainCircuit aria-hidden className="size-5" />} title="Local security model">
            A 7B model in Ollama catches what regex misses. It <em>masks</em> a value (reversible placeholder, real value
            kept in RAM) or <em>collapses</em> noisy output into a one-line summary.
          </Step>
          <Step n={3} icon={<RotateCcw aria-hidden className="size-5" />} title="Restore">
            When the model calls a tool, placeholders in its arguments become real values again, locally. Commands run
            on real paths; the relay never saw them.
          </Step>
        </ol>
        <p className="mt-6 flex items-start gap-3 rounded-lg border border-leak/40 bg-leak/6 p-4 text-pretty">
          <Ban aria-hidden className="mt-0.5 size-5 shrink-0 text-leak" />
          <span>
            <strong className="font-semibold">Fails closed.</strong> If the security model breaks, the request is
            blocked with HTTP 502. Nothing goes upstream raw.
          </span>
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Link
            href="/demo"
            className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85"
          >
            See it on six real tasks <ArrowRight aria-hidden className="size-4" />
          </Link>
          <Link
            href="/how-it-works"
            className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent"
          >
            How it works
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
        More on {defense} <ArrowRight aria-hidden className="size-4" />
      </Link>
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
