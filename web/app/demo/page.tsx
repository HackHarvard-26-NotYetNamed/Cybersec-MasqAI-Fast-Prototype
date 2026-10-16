import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { ReplayTheater } from "@/components/replay/theater";

export const metadata: Metadata = {
  title: "Replay theater",
  description: "Six recorded agent sessions, side by side: what the agent sent versus what the relay saw.",
};

export default function DemoPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-6 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="Replay theater" title="Same session, two views">
        Each replay is a recorded coding-agent session from the synthetic playground. On the left is what the agent
        produced. On the right is what the untrusted relay received. Flip <strong className="text-foreground">Without
        MasqAI</strong> to see the baseline.
      </PageIntro>
      <ReplayTheater />
    </div>
  );
}
