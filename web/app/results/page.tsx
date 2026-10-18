import type { Metadata } from "next";
import { PageIntro } from "@/components/site/page-bits";
import { ResultsView } from "@/components/results/results-view";

export const metadata: Metadata = {
  title: "Evaluation",
  description: "Leak rate, task success, token use and latency per use case, with and without MasqAI.",
};

export default function ResultsPage() {
  return (
    <div className="mx-auto max-w-7xl space-y-8 px-4 py-8 sm:px-6 sm:py-10">
      <PageIntro eyebrow="Evaluation" title="What MasqAI costs, and what it buys" />
      <ResultsView />
    </div>
  );
}
