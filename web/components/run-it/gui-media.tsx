"use client";

import { ImageOff } from "lucide-react";
import { MediaSchema, useJson } from "@/lib/data";
import { DataError, Loading } from "@/components/site/page-bits";
import { cn } from "@/lib/utils";

/** Screenshots or short loops of the gateway's built-in GUI, listed in /media/media.json. */
export function GuiMedia() {
  const media = useJson("/media/media.json", MediaSchema);
  if (media.status === "loading") return <Loading label="Loading media" />;
  if (media.status === "error") return <DataError url={media.url} message={media.message} />;
  if (media.data.items.length === 0)
    return (
      <div className="flex min-h-56 flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed bg-card p-6 text-center">
        <ImageOff aria-hidden className="size-8 text-muted-foreground" />
        <p className="font-medium">A recording of the gateway GUI goes here</p>
        <p className="max-w-md text-sm text-muted-foreground">
          Add a screenshot or a short looping video to <code className="font-mono">public/media/</code> and list it in{" "}
          <code className="font-mono">media.json</code>. Record it with synthetic playground data only.
        </p>
      </div>
    );
  return (
    <div className={cn("grid gap-4", media.data.items.length > 1 && "lg:grid-cols-2")}>
      {media.data.items.map((item) => (
        <figure key={item.src} className="overflow-hidden rounded-xl border bg-card">
          {item.kind === "video" ? (
            <video src={item.src} aria-label={item.alt} autoPlay muted loop playsInline controls className="w-full" />
          ) : (
            // eslint-disable-next-line @next/next/no-img-element -- static files of unknown size from media.json
            <img src={item.src} alt={item.alt} className="w-full" />
          )}
          {item.caption ? <figcaption className="border-t px-4 py-2 text-sm text-muted-foreground">{item.caption}</figcaption> : null}
        </figure>
      ))}
    </div>
  );
}
