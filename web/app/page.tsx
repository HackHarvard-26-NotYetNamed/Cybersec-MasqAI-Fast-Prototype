import Link from "next/link";
import { ArrowRight, Boxes, Check, KeyRound, ScanSearch, ShieldCheck, SlidersHorizontal, Sparkles, Telescope } from "lucide-react";
import { DaytonaRuns } from "@/components/landing/daytona-runs";
import { LeakStrip } from "@/components/landing/leak-strip";
import { MirrorHero } from "@/components/landing/mirror";
import { PipelineFlow } from "@/components/landing/pipeline-flow";
import rules from "@/lib/detector-rules.json";

/*
 * The home page follows the pitch script top to bottom:
 *   Skyll   → hero: the leak in three beats, then the mirror (what an agent sends vs. what it should)
 *   Matthew → /try and /demo (their own pages)
 *   Andy    → "Every request, inspected before it leaves": the animated pipeline
 *   Esme    → "MasqAI protects the context. Daytona contains the actions.": the 30 runs
 * Everything below Esme's section is for judges browsing afterwards.
 */
export default function Home() {
  return (
    <>
      <section className="bg-grid border-b">
        <div className="mx-auto max-w-7xl px-4 pt-10 pb-12 sm:px-6 sm:pt-14">
          <h1 className="max-w-4xl text-4xl font-semibold tracking-tight text-balance sm:text-6xl">
            Your LLM key is a two-way mirror. <span className="text-restored">MasqAI makes it one-way.</span>
          </h1>
          <div className="mt-7">
            <LeakStrip />
          </div>
          <div className="mt-8">
            <MirrorHero />
          </div>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/try" className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85">
              Try it live <ArrowRight aria-hidden className="size-4" />
            </Link>
            <Link href="/demo" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
              Watch the replays
            </Link>
          </div>
        </div>
      </section>

      <section aria-labelledby="pipeline" className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
        <Heading id="pipeline" eyebrow="How it works">
          Every request, inspected before it leaves
        </Heading>
        <div className="mt-6">
          <PipelineFlow />
        </div>
      </section>

      <section aria-labelledby="daytona" className="border-t bg-card/40">
        <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
          <Heading id="daytona" eyebrow="Measured in Daytona sandboxes" icon={<Boxes aria-hidden className="size-4" />}>
            MasqAI protects the context. Daytona contains the actions.
          </Heading>
          <div className="mt-6">
            <DaytonaRuns />
          </div>
          <div className="mt-5 flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-wrap gap-3">
              <Link href="/results" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
                See the numbers <ArrowRight aria-hidden className="size-4" />
              </Link>
              <Link href="/how-it-works#daytona-title" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
                How we use Daytona
              </Link>
            </div>
            {/* The close of the pitch: "try it right now on our site". */}
            <Link href="/try" className="flex items-center gap-4 rounded-xl border bg-card p-3 pr-5 hover:bg-accent/40">
              {/* eslint-disable-next-line @next/next/no-img-element -- a static SVG, scaled crisp */}
              <img src="/qr-try.svg" alt="QR code for masqai.vercel.app/try" width={104} height={104} className="rounded-md" />
              <span>
                <span className="block text-lg font-semibold">Try it now</span>
                <span className="font-mono text-sm text-muted-foreground">masqai.vercel.app/try</span>
              </span>
            </Link>
          </div>
        </div>
      </section>

      <section aria-labelledby="choose" className="border-t">
        <div className="mx-auto grid max-w-7xl gap-6 px-4 py-14 sm:px-6 lg:grid-cols-[1fr_1.4fr] lg:items-center">
          <div>
            <Heading id="choose" eyebrow="Your rules, not a preset" icon={<SlidersHorizontal aria-hidden className="size-4" />}>
              You decide what counts as secret
            </Heading>
            <Link href="/try" className="mt-5 inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85">
              Try the switches <ArrowRight aria-hidden className="size-4" />
            </Link>
          </div>
          <div className="space-y-3">
            {(["secret", "intel"] as const).map((kind) => (
              <ul key={kind} aria-label={kind === "secret" ? "Secrets, masked" : "Intel, hidden or replaced"} className="flex flex-wrap gap-2">
                {rules.categories.filter((c) => c.kind === kind).map((c) => (
                  <li key={c.id} title={c.description} className="inline-flex items-center gap-1.5 rounded-full border border-restored/50 bg-restored/10 px-3.5 py-1.5">
                    {kind === "secret" ? <Check aria-hidden className="size-4 text-restored" /> : <Sparkles aria-hidden className="size-4 text-model" />}
                    {c.label}
                  </li>
                ))}
              </ul>
            ))}
          </div>
        </div>
      </section>

      <section aria-labelledby="secret-intel" className="border-t bg-card/40">
        <div className="mx-auto grid max-w-7xl gap-4 px-4 py-14 sm:px-6 md:grid-cols-2">
          <h2 id="secret-intel" className="text-3xl font-semibold tracking-tight md:col-span-2 sm:text-4xl">
            Secrets are masked. Intel is hidden.
          </h2>
          <Kind
            icon={<KeyRound aria-hidden className="size-5 text-leak" />}
            title="Secret"
            handling="masked · restored in tool calls"
            examples={["sk-or-v1-FAKEFAKE5e2b…", "C:\\Users\\alice\\…\\inventory.db", "DESKTOP-7Q2XK9M"]}
          />
          <Kind
            icon={<Telescope aria-hidden className="size-5 text-replaced" />}
            title="Intel"
            handling="hidden or replaced · never restored"
            examples={["“a short walk from Davis Square”", "an env dump with every drive and tool", "an unreleased design doc"]}
          />
        </div>
      </section>

      <section aria-labelledby="threats" className="border-t">
        <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6">
          <Heading id="threats" eyebrow="Two assets, two defenses">
            The key and the context
          </Heading>
          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <Threat
              icon={<KeyRound aria-hidden className="size-6 text-ent-key" />}
              asset="The key"
              threat="whoever obtains it"
              defense="Key Enigma"
              text="Rotates your provider key on a timer, so a leaked key dies fast."
              status="In progress"
              href="/trust"
            />
            <Threat
              icon={<ScanSearch aria-hidden className="size-6 text-ent-path" />}
              asset="The context"
              threat="whoever runs the endpoint"
              defense="The sanitizer"
              text="Masks secrets and strips intel before anything leaves; restores real values locally."
              status="Working"
              href="/how-it-works"
            />
          </div>
        </div>
      </section>
    </>
  );
}

function Heading({ id, eyebrow, icon, children }: { id: string; eyebrow: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div>
      <p className="flex items-center gap-2 font-mono text-sm tracking-wide text-muted-foreground uppercase">
        {icon}
        {eyebrow}
      </p>
      <h2 id={id} className="mt-2 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">
        {children}
      </h2>
    </div>
  );
}

function Kind({ icon, title, handling, examples }: { icon: React.ReactNode; title: string; handling: string; examples: string[] }) {
  return (
    <article className="rounded-xl border bg-card p-5">
      <h3 className="flex flex-wrap items-baseline gap-x-3 text-xl font-semibold">
        <span className="inline-flex items-center gap-2">
          {icon}
          {title}
        </span>
        <span className="text-sm font-normal text-muted-foreground">{handling}</span>
      </h3>
      <ul className="mt-4 space-y-2">
        {examples.map((example) => (
          <li key={example} className="rounded-md border bg-background px-3 py-2 font-mono text-[15px] break-all">
            {example}
          </li>
        ))}
      </ul>
    </article>
  );
}

function Threat({ icon, asset, threat, defense, text, status, href }: {
  icon: React.ReactNode;
  asset: string;
  threat: string;
  defense: string;
  text: string;
  status: string;
  href: string;
}) {
  return (
    <Link href={href} className="group flex flex-col rounded-xl border bg-card p-5 hover:bg-accent/40">
      <p className="flex items-center gap-3 text-xl font-semibold">
        {icon}
        {asset}
        <span className="text-base font-normal text-muted-foreground">· threat: {threat}</span>
      </p>
      <p className="mt-4 flex items-center gap-2 text-lg font-semibold">
        <ShieldCheck aria-hidden className="size-5 text-restored" />
        {defense}
        <span className="rounded-full border px-2 py-0.5 font-mono text-xs font-normal">{status}</span>
      </p>
      <p className="mt-1 text-muted-foreground">{text}</p>
      <span className="mt-3 inline-flex items-center gap-1 font-medium group-hover:underline">
        More <ArrowRight aria-hidden className="size-4" />
      </span>
    </Link>
  );
}
