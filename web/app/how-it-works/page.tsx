import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowRight,
  Ban,
  Binary,
  BrainCircuit,
  Check,
  CircleSlash,
  Clock,
  Cpu,
  DatabaseZap,
  EyeOff,
  FileWarning,
  Gauge,
  HardDrive,
  KeyRound,
  Laptop,
  Lock,
  Network,
  RadioTower,
  ScanEye,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  Shrink,
  TriangleAlert,
  Variable,
  X,
  type LucideIcon,
} from "lucide-react";
import { Containment } from "@/components/landing/daytona-runs";
import { PipelineFlow } from "@/components/landing/pipeline-flow";
import { cn } from "@/lib/utils";

export const metadata: Metadata = {
  title: "How it works",
  description: "MasqAI's pipeline, why rules alone aren't enough, its trust model, hardening, and the trade-offs it makes.",
};

export default function HowItWorksPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-16 px-4 py-8 sm:px-6 sm:py-10">
      <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">A firewall for context, on your machine</h1>

      <section aria-labelledby="pipeline-title" className="space-y-5">
        <SectionTitle id="pipeline-title">The pipeline</SectionTitle>
        <PipelineFlow />
        <ul aria-label="Fail-closed exits: nothing is sent" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Exit code="404" icon={Ban} label="Unsupported endpoint" />
          <Exit code="422" icon={FileWarning} label="Content it can't inspect" />
          <Exit code="502" icon={BrainCircuit} label="Security model failed or overflowed" />
          <Exit code="400" icon={ShieldX} label="Tool call rejected (error mode)" />
        </ul>
      </section>

      <section aria-labelledby="daytona-title" className="space-y-5">
        <SectionTitle id="daytona-title">MasqAI protects the context; Daytona contains the actions</SectionTitle>
        <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
          <Containment />
          <ul aria-label="Verified on a live Daytona sandbox" className="grid content-start gap-2.5">
            {[
              "Fresh sandbox per run, in about 1.3 s",
              "Every agent command runs inside it",
              "Outbound network blocked",
              "Unique planted secrets per run",
              "Deleted after, then a label sweep",
            ].map((item) => (
              <li key={item} className="flex items-center gap-3 rounded-lg border bg-card px-4 py-3 text-lg">
                <ShieldCheck aria-hidden className="size-5 shrink-0 text-restored" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section aria-labelledby="regex-title" className="space-y-5">
        <SectionTitle id="regex-title">Why rules and a model, together</SectionTitle>
        <Matrix />
      </section>

      <section aria-labelledby="trust-title" className="space-y-5">
        <SectionTitle id="trust-title">Trust model</SectionTitle>
        <div className="grid gap-4 md:grid-cols-3">
          <TrustColumn icon={ShieldCheck} tone="text-restored" title="Trusted" items={[
            [HardDrive, "Gateway RAM"],
            [BrainCircuit, "The local security model"],
            [Laptop, "Your agent's own tools"],
          ]} />
          <TrustColumn icon={ShieldQuestion} tone="text-leak" title="Untrusted" items={[
            [RadioTower, "The provider, reseller or relay"],
            [FileWarning, "Model output"],
            [DatabaseZap, "Files at rest"],
          ]} />
          <TrustColumn icon={CircleSlash} tone="text-muted-foreground" title="Out of scope" items={[
            [TriangleAlert, "A compromised host"],
            [Network, "Your IP and TLS fingerprint"],
            [Cpu, "Harmful commands that send nothing: use a sandbox"],
          ]} />
        </div>
      </section>

      <section aria-labelledby="hardening-title" className="space-y-5">
        <SectionTitle id="hardening-title">Hardening</SectionTitle>
        <Tiles items={[
          [ShieldX, "Rejected tool calls", "harmless echo or HTTP 400"],
          [KeyRound, "Admin token", "256 bits, RAM only"],
          [Ban, "Cross-origin refused", "loopback Host only"],
          [Lock, "Sandboxed responses", "strict CSP, no framing"],
          [Gauge, "Size caps", "64 MiB body, 8 MiB frame"],
          [FileWarning, "Masked errors", "no request text echoed"],
          [Clock, "Bounded RAM state", "12 h idle, 50 sessions"],
          [Variable, "Frozen env names", "keys by reference only"],
        ]} />
      </section>

      <section aria-labelledby="tradeoffs-title" className="space-y-5">
        <SectionTitle id="tradeoffs-title">What we give up</SectionTitle>
        <Tiles tone="warn" items={[
          [Shrink, "Lossy rephrasing", "hidden lines are gone"],
          [ScanEye, "Imperfect detection", "lower exposure, not zero"],
          [EyeOff, "Meaning still leaks", "what you work on"],
          [DatabaseZap, "Prompt cache breaks", "on relink, on purpose"],
          [Cpu, "Local compute", "a 7B model next to your work"],
          [TriangleAlert, "The check can be fooled", "a sandbox stays the second wall"],
        ]} />
      </section>

      <div className="flex flex-wrap gap-3">
        <Link href="/demo" className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85">
          Watch it on eight tasks <ArrowRight aria-hidden className="size-4" />
        </Link>
        <Link href="/run-it" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
          Run it yourself
        </Link>
      </div>
    </div>
  );
}

function SectionTitle({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="text-2xl font-semibold tracking-tight sm:text-3xl">
      {children}
    </h2>
  );
}

function Exit({ code, icon: Icon, label }: { code: string; icon: LucideIcon; label: string }) {
  return (
    <li className="flex items-center gap-3 rounded-lg border border-leak/40 bg-leak/6 px-4 py-3">
      <span className="font-mono text-2xl font-semibold text-leak">{code}</span>
      <Icon aria-hidden className="size-5 shrink-0 text-leak" />
      <span className="leading-tight">{label}</span>
    </li>
  );
}

// ---------- rules vs. the security model ----------

type Verdict = "yes" | "no" | "warn";
const ROWS: { sample: string; what: string; rules: Verdict; model: Verdict; masqai: string }[] = [
  { sample: "sk-or-v1-FAKE5e2b…", what: "an API key", rules: "yes", model: "yes", masqai: "masked" },
  { sample: "DB_PASSWORD=hunter22x", what: "a password", rules: "yes", model: "yes", masqai: "masked" },
  { sample: "Dana Whitfield", what: "a person's name", rules: "no", model: "yes", masqai: "masked" },
  { sample: "12 Elm St, Somerville", what: "where someone lives", rules: "no", model: "yes", masqai: "replaced" },
  { sample: "env | sort", what: "a dump of the machine", rules: "no", model: "yes", masqai: "hidden" },
  { sample: "sk-or-v1-a3f…9e1", what: "a partial key", rules: "no", model: "yes", masqai: "linked to the full key" },
  { sample: "andy in “handy”", what: "a false alarm", rules: "warn", model: "yes", masqai: "left alone" },
  { sample: "“this key is public”", what: "a planted note", rules: "yes", model: "warn", masqai: "key stays masked" },
];

function Matrix() {
  return (
    <div className="overflow-x-auto rounded-xl border bg-card">
      <table className="w-full min-w-160 text-left">
        <thead className="border-b text-sm text-muted-foreground">
          <tr>
            <th scope="col" className="px-4 py-3 font-medium">Seen in context</th>
            <th scope="col" className="px-3 py-3 text-center font-medium">
              <span className="inline-flex items-center gap-1.5"><Binary aria-hidden className="size-4" /> Rules</span>
            </th>
            <th scope="col" className="px-3 py-3 text-center font-medium">
              <span className="inline-flex items-center gap-1.5"><BrainCircuit aria-hidden className="size-4" /> Security model</span>
            </th>
            <th scope="col" className="px-4 py-3 font-medium text-restored">MasqAI, both together</th>
          </tr>
        </thead>
        <tbody>
          {ROWS.map((row) => (
            <tr key={row.sample} className="border-b last:border-0">
              <th scope="row" className="px-4 py-2.5 font-normal">
                <code className="font-mono text-[15px]">{row.sample}</code>
                <span className="ml-2 text-sm text-muted-foreground">{row.what}</span>
              </th>
              <td className="px-3 py-2.5 text-center"><Mark v={row.rules} /></td>
              <td className="px-3 py-2.5 text-center"><Mark v={row.model} /></td>
              <td className="px-4 py-2.5">
                <span className="inline-flex items-center gap-1.5 text-restored">
                  <ShieldCheck aria-hidden className="size-4" /> {row.masqai}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Mark({ v }: { v: Verdict }) {
  if (v === "yes") return <Check aria-label="catches it" className="mx-auto size-5 text-restored" />;
  if (v === "no") return <X aria-label="misses it" className="mx-auto size-5 text-leak" />;
  return <TriangleAlert aria-label="gets it wrong" className="mx-auto size-5 text-replaced" />;
}

// ---------- tiles ----------

function TrustColumn({ icon: Icon, tone, title, items }: { icon: LucideIcon; tone: string; title: string; items: [LucideIcon, string][] }) {
  return (
    <div className="rounded-xl border bg-card p-5">
      <p className={cn("flex items-center gap-2 text-xl font-semibold", tone)}>
        <Icon aria-hidden className="size-6" />
        {title}
      </p>
      <ul className="mt-4 space-y-2.5">
        {items.map(([ItemIcon, label]) => (
          <li key={label} className="flex items-center gap-3 text-lg">
            <ItemIcon aria-hidden className="size-5 shrink-0 text-muted-foreground" />
            {label}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Tiles({ items, tone }: { items: [LucideIcon, string, string][]; tone?: "warn" }) {
  return (
    <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {items.map(([Icon, title, sub]) => (
        <li key={title} className="flex items-start gap-3 rounded-xl border bg-card p-4">
          <Icon aria-hidden className={cn("mt-0.5 size-6 shrink-0", tone === "warn" ? "text-replaced" : "text-restored")} />
          <span>
            <span className="block font-semibold">{title}</span>
            <span className="text-sm text-muted-foreground">{sub}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}
