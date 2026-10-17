import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { Playground } from "@/components/try/playground";

export const metadata: Metadata = {
  title: "Try it",
  description: "Paste agent context and watch MasqAI's detector rules mask it, live, in your browser.",
};

export default function TryPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-5 px-4 py-6 sm:px-6 sm:py-8">
      <PageIntro eyebrow="Live playground" title="Try it: nothing leaves this page">
        Edit the left side, or switch off what you don&apos;t need protected. The right side is what the untrusted
        model would receive.
      </PageIntro>
      <Playground />
    </div>
  );
}
