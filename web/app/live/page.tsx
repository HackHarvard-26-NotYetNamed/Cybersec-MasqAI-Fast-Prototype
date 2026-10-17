import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { LiveView } from "@/components/live/live-view";

export const metadata: Metadata = {
  title: "Live",
  description: "Read a locally running MasqAI gateway. Local development only.",
};

export default function LivePage() {
  return (
    <div className="mx-auto max-w-7xl space-y-8 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="Live (local only)" title="Your gateway, as it runs">
        When you run this site on your own machine next to the gateway, this page follows its sanitize passes in real
        time.
      </PageIntro>
      <LiveView />
    </div>
  );
}
