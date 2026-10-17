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
      <PageIntro eyebrow="Protecting the key" title="Key Enigma and honeytokens">
        The sanitizer protects what you send. These two features protect the key you send it with. Both are planned
        for this weekend; the timeline below is simulated.
      </PageIntro>

      <div className="grid gap-4 md:grid-cols-2">
        <article className="rounded-xl border bg-card p-5">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <KeyRound aria-hidden className="size-5 text-ent-key" />
            Key Enigma
          </h2>
          <p className="mt-2 text-pretty text-muted-foreground">
            MasqAI holds the provider credentials and keeps issuing short-lived upstream keys. Each key is active for a
            few minutes, stays valid for a short grace period so in-flight requests finish, then is revoked. A key that
            leaks stops working soon after.
          </p>
        </article>
        <article className="rounded-xl border bg-card p-5">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <Radar aria-hidden className="size-5 text-leak" />
            Honeytokens
          </h2>
          <p className="mt-2 text-pretty text-muted-foreground">
            MasqAI plants a canary key in outgoing context. Nothing legitimate ever uses it. If it is ever used, the
            endpoint that saw it was logging and reusing your traffic, and MasqAI marks that endpoint untrustworthy.
          </p>
        </article>
      </div>

      <KeyTrust />
    </div>
  );
}
