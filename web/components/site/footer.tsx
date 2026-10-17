import { FlaskConical } from "lucide-react";

export function SiteFooter() {
  return (
    <footer className="border-t">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-5 text-sm text-muted-foreground sm:px-6">
        <p>
          MasqAI · HackHarvard 2026, cybersecurity track. The gateway runs only on your machine; this site is a static
          showcase.
        </p>
        <p
          className="inline-flex items-center gap-2 rounded-full border border-foreground/40 bg-card px-3 py-1 font-mono text-xs font-medium text-foreground"
          title="Every value on this site comes from the project's synthetic playground secrets."
        >
          <FlaskConical aria-hidden className="size-3.5" />
          Synthetic demo data
        </p>
      </div>
    </footer>
  );
}
