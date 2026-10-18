"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Code2, VenetianMask } from "lucide-react";
import { ThemeToggle } from "./theme-toggle";
import { cn } from "@/lib/utils";

// In the order the story is told: try it, watch it, how, the numbers, then the rest.
const LINKS = [
  { href: "/try", label: "Try it" },
  { href: "/demo", label: "Demo" },
  { href: "/how-it-works", label: "How it works" },
  { href: "/results", label: "Results" },
  { href: "/trust", label: "Key Enigma" },
  { href: "/run-it", label: "Run it" },
] as const;

export function SiteHeader() {
  const pathname = usePathname();
  return (
    <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-1.5 px-4 py-2 sm:flex-nowrap sm:px-6 sm:py-3">
        <Link href="/" className="flex shrink-0 items-center gap-2 font-mono text-base font-semibold tracking-tight">
          <VenetianMask aria-hidden className="size-5 text-restored" />
          MasqAI
        </Link>
        {/* Phones: one row that scrolls sideways, so the sticky header stays short. */}
        <nav aria-label="Main" className="order-3 -mx-4 w-[calc(100%+2rem)] overflow-x-auto px-4 [scrollbar-width:none] sm:order-none sm:mx-0 sm:w-auto sm:flex-1 sm:px-0 [&::-webkit-scrollbar]:hidden">
          <ul className="flex gap-1 whitespace-nowrap">
            {LINKS.map(({ href, label }) => {
              const active = pathname === href;
              return (
                <li key={href}>
                  <Link
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "inline-flex min-h-9 items-center rounded-md px-3 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
                      active && "bg-accent text-foreground",
                    )}
                  >
                    {label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className="ml-auto flex items-center gap-2 sm:ml-0">
          <a
            href="https://github.com/HackHarvard-26-NotYetNamed/Cybersec-MasqAI-Fast-Prototype"
            className="inline-flex min-h-9 items-center gap-1.5 rounded-md border px-3 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            <Code2 aria-hidden className="size-4" />
            Code
          </a>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
