"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Laptop, RadioTower } from "lucide-react";
import { PlaceholderChip, SecretMark } from "@/components/replay/annotated-text";
import type { ChipType } from "@/lib/ops";

type Seg = string | { value: string; placeholder: string; type: ChipType };

// Synthetic values from the playground.
const LINES: Seg[][] = [
  ["$ sqlite3 \"", { value: "C:\\Users\\alice\\AppData\\Local\\AcmeInventory\\prod\\inventory.db", placeholder: "<PATH_b71e04d2>", type: "PATH" }, "\""],
  ["API_KEY = \"", { value: "sk-or-v1-FAKE5e2b7a90c4d1f8e3", placeholder: "<OR_KEY_913fb303>", type: "KEY" }, "\""],
  ["author: ", { value: "Dana Whitfield", placeholder: "<IDENTITY_4be0a1c7>", type: "USER" }, " ", { value: "dana.whitfield7f3c@acme-robotics.dev", placeholder: "<EMAIL_92d3f0b8>", type: "EMAIL" }],
  ["COMPUTERNAME ", { value: "DESKTOP-7Q2XK9M", placeholder: "<HOST_6d2e81f0>", type: "HOST" }, "  USERNAME ", { value: "alice", placeholder: "<USERNAME_a4b19e57>", type: "USER" }],
];

const LINE_MS = 1100;
const HOLD_MS = 3200;

function useCrossing(reduce: boolean | null) {
  // 0..LINES.length = how many lines have crossed. Loops while motion is allowed.
  const [crossed, setCrossed] = useState(reduce ? LINES.length : 0);
  useEffect(() => {
    if (reduce) return;
    const id = setTimeout(
      () => setCrossed((n) => (n >= LINES.length ? 0 : n + 1)),
      crossed >= LINES.length ? HOLD_MS : crossed === 0 ? 700 : LINE_MS,
    );
    return () => clearTimeout(id);
  }, [crossed, reduce]);
  return reduce ? LINES.length : crossed;
}

export function MirrorHero() {
  const reduce = useReducedMotion();
  const crossed = useCrossing(reduce);
  return (
    <figure
      aria-label="The same request on both sides of MasqAI: real values on your machine, placeholders at the relay."
      className="relative grid overflow-hidden rounded-xl border bg-card shadow-sm md:grid-cols-[1fr_auto_1fr]"
    >
      <Side title="Your machine" subtitle="the agent sends real values" icon={<Laptop aria-hidden className="size-4" />}>
        {LINES.map((line, i) => (
          <Line key={i} active={i === crossed && crossed < LINES.length}>
            {line.map((seg, j) =>
              typeof seg === "string" ? seg : <SecretMark key={j} text={seg.value} type={seg.type} />,
            )}
          </Line>
        ))}
      </Side>

      <div aria-hidden className="relative flex items-center justify-center md:w-14">
        <div className="absolute inset-x-0 top-1/2 h-px bg-gradient-to-r from-transparent via-restored/80 to-transparent md:inset-x-auto md:inset-y-0 md:top-0 md:h-auto md:w-px md:bg-gradient-to-b" />
        <span className="relative my-2 rounded-full border border-restored/60 bg-background px-2 py-1 font-mono text-xs font-semibold tracking-wider text-restored md:my-0 md:[writing-mode:vertical-rl]">
          MASQAI
        </span>
      </div>

      <Side title="The relay" subtitle="the operator sees placeholders" icon={<RadioTower aria-hidden className="size-4" />}>
        {LINES.map((line, i) => (
          <Line key={i} dim={i >= crossed}>
            {line.map((seg, j) =>
              typeof seg === "string" ? (
                seg
              ) : (
                <AnimatePresence key={j} mode="popLayout" initial={false}>
                  {i < crossed ? (
                    <motion.span
                      key="chip"
                      initial={{ opacity: 0, scale: 0.8 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ duration: 0.35, delay: j * 0.08 }}
                      className="inline-block"
                    >
                      <PlaceholderChip placeholder={seg.placeholder} type={seg.type} />
                    </motion.span>
                  ) : (
                    <motion.span key="pending" exit={{ opacity: 0 }} className="text-muted-foreground">
                      {"·".repeat(Math.min(12, seg.placeholder.length))}
                    </motion.span>
                  )}
                </AnimatePresence>
              ),
            )}
          </Line>
        ))}
      </Side>
    </figure>
  );
}

function Side({
  title,
  subtitle,
  icon,
  children,
}: {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0 p-4 sm:p-5">
      <p className="mb-3 flex flex-wrap items-baseline gap-x-2 text-sm">
        <span className="inline-flex items-center gap-1.5 font-semibold">
          {icon}
          {title}
        </span>
        <span className="text-muted-foreground">{subtitle}</span>
      </p>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function Line({ children, active, dim }: { children: React.ReactNode; active?: boolean; dim?: boolean }) {
  return (
    <p
      className={`rounded-md px-2 py-1 font-mono text-[15px] leading-relaxed whitespace-pre-wrap transition-colors [overflow-wrap:anywhere] ${
        active ? "bg-foreground/5" : ""
      } ${dim ? "text-muted-foreground" : ""}`}
    >
      {children}
    </p>
  );
}
