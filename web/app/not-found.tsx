import Link from "next/link";
import { ArrowRight, VenetianMask } from "lucide-react";

export default function NotFound() {
  return (
    <div className="mx-auto flex min-h-[60vh] max-w-3xl flex-col items-center justify-center gap-6 px-4 py-16 text-center">
      <VenetianMask aria-hidden className="size-14 text-restored" />
      <p className="font-mono text-2xl sm:text-3xl">
        GET{" "}
        <span className="rounded border border-ent-path/55 bg-ent-path/12 px-2 py-0.5 text-ent-path">&lt;PAGE_404c0de5&gt;</span>
      </p>
      <h1 className="text-2xl font-semibold">This page is masked. Or it never existed.</h1>
      <div className="flex flex-wrap justify-center gap-3">
        <Link href="/" className="inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-5 font-medium text-primary-foreground hover:bg-primary/85">
          Home <ArrowRight aria-hidden className="size-4" />
        </Link>
        <Link href="/try" className="inline-flex min-h-11 items-center gap-2 rounded-md border bg-card px-5 font-medium hover:bg-accent">
          Try it live
        </Link>
      </div>
    </div>
  );
}
