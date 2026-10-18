import type { Metadata } from "next";
import { KeyRound, Radar } from "lucide-react";
import { PageIntro } from "@/components/site/page-bits";
import { KeyTrust } from "@/components/trust/key-timeline";

export const metadata: Metadata = {
  title: "Key Enigma and honeytokens",
  description: "Rotating the upstream key so a leaked key dies quickly, and canary keys that catch relays reusing traffic.",
};

export default function TrustPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-8 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="Protecting the key" title="Key Enigma and honeytokens" />

      <div className="grid gap-4 md:grid-cols-2">
        <article className="rounded-xl border bg-card p-5">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <KeyRound aria-hidden className="size-5 text-ent-key" />
            Key Enigma
          </h2>
          <p className="mt-2 text-lg text-pretty text-muted-foreground">A fresh key every 15 minutes: a leaked one dies fast.</p>
          <p className="mt-2 inline-flex rounded-full border px-2.5 py-0.5 font-mono text-xs">In progress · key leases done</p>
        </article>
        <article className="rounded-xl border bg-card p-5">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Radar aria-hidden className="size-5 text-leak" />
            Honeytokens
          </h2>
          <p className="mt-2 text-lg text-pretty text-muted-foreground">A planted canary key: if it&apos;s ever used, the endpoint is logging you.</p>
          <p className="mt-2 inline-flex rounded-full border px-2.5 py-0.5 font-mono text-xs">Planned</p>
        </article>
      </div>

      <KeyTrust />
    </div>
  );
}
