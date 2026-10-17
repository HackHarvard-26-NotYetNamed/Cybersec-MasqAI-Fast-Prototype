import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { ReplayTheater } from "@/components/replay/theater";

export const metadata: Metadata = {
  title: "Replay theater",
  description: "Six recorded agent sessions, side by side: what the agent sent versus what the relay saw.",
};

export default function DemoPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-4 px-4 py-6 sm:px-6">
      <PageIntro eyebrow="Replay theater" title="Same session, two views">
        Left: what the agent sent. Right: what the untrusted model received. Flip{" "}
        <strong className="text-foreground">Without MasqAI</strong> for the baseline.
      </PageIntro>
      <ReplayTheater />
    </div>
  );
}
