import type { Metadata } from "next";
import { Teleprompter } from "@/components/present/teleprompter";

export const metadata: Metadata = {
  title: "Presenter",
  description: "Cue cards for the MasqAI pitch.",
  robots: { index: false, follow: false },
};

export default function PresentPage() {
  return <Teleprompter />;
}
