import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { Playground } from "@/components/try/playground";

export const metadata: Metadata = {
  title: "Try it",
  description: "Paste agent context and watch MasqAI's detector rules mask it, live, in your browser.",
};

export default function TryPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-3 px-4 py-5 sm:px-6">
      <PageIntro eyebrow="Live playground" title="Try it: nothing leaves this page" />
      <Playground />
    </div>
  );
}
