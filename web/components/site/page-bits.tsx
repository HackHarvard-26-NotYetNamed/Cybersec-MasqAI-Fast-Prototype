import { FileWarning, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

export function PageIntro({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <div className="max-w-3xl">
      <p className="font-mono text-sm tracking-wide text-muted-foreground uppercase">{eyebrow}</p>
      <h1 className="mt-2 text-3xl font-semibold tracking-tight text-balance sm:text-4xl">{title}</h1>
      {children ? <div className="mt-3 text-lg text-pretty text-muted-foreground">{children}</div> : null}
    </div>
  );
}

export function DataError({ url, message }: { url: string; message: string }) {
  return (
    <div role="alert" className="rounded-lg border border-leak/50 bg-leak/8 p-5">
      <p className="flex items-center gap-2 font-semibold text-leak">
        <FileWarning aria-hidden className="size-5" />
        This data file could not be loaded
      </p>
      <p className="mt-2 text-muted-foreground">
        <code className="font-mono text-foreground">{url}</code> is missing or does not match the expected format. The
        rest of the site still works. Details:
      </p>
      <pre className="mt-3 max-h-60 overflow-auto rounded-md bg-muted p-3 font-mono text-sm whitespace-pre-wrap">
        {message}
      </pre>
    </div>
  );
}

export function Loading({ label = "Loading data" }: { label?: string }) {
  return (
    <p role="status" className="flex items-center gap-2 py-10 text-muted-foreground">
      <Loader2 aria-hidden className="size-4 animate-spin" />
      {label}…
    </p>
  );
}
