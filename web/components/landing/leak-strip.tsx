"use client";

import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, Fingerprint, FolderTree, KeyRound, UserRound, Users } from "lucide-react";

/** The origin story as three beats: one leaked key → ~40 other keys' traffic → what it exposed. Counts only. */
export function LeakStrip() {
  const reduce = useReducedMotion();
  const beat = (i: number) => ({
    initial: reduce ? false : { y: 12, filter: "blur(6px)" },
    whileInView: { y: 0, filter: "blur(0px)" },
    viewport: { once: true, amount: 0.6 },
    transition: { duration: 0.5, delay: 0.25 + i * 0.45 },
  });
  return (
    <div
      role="group"
      aria-label="What one leaked key showed us: traffic from about 40 other keys, exposing machine fingerprints, database paths, and chat names with emails."
      className="flex flex-wrap items-center gap-3 sm:gap-4"
    >
      <motion.div {...beat(0)} className="flex items-center gap-3 rounded-xl border border-leak/50 bg-leak/8 px-4 py-3">
        <KeyRound aria-hidden className="size-7 text-leak" />
        <p className="leading-tight">
          <span className="block font-mono text-3xl font-semibold">1</span>
          <span className="text-sm text-muted-foreground">leaked key</span>
        </p>
      </motion.div>
      <motion.span {...beat(0.6)}>
        <ArrowRight aria-hidden className="size-6 text-muted-foreground" />
      </motion.span>
      <motion.div {...beat(1)} className="flex items-center gap-3 rounded-xl border px-4 py-3">
        <Users aria-hidden className="size-7" />
        <p className="leading-tight">
          <span className="block font-mono text-3xl font-semibold">≈40</span>
          <span className="text-sm text-muted-foreground">other keys&apos; traffic seen</span>
        </p>
      </motion.div>
      <motion.span {...beat(1.6)}>
        <ArrowRight aria-hidden className="size-6 text-muted-foreground" />
      </motion.span>
      <motion.ul {...beat(2)} className="flex flex-wrap gap-2">
        {[
          { icon: Fingerprint, text: "OS fingerprints", tone: "text-ent-host" },
          { icon: FolderTree, text: "database paths", tone: "text-ent-path" },
          { icon: UserRound, text: "chat names + emails", tone: "text-ent-user" },
        ].map(({ icon: Icon, text, tone }) => (
          <li key={text} className="flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm">
            <Icon aria-hidden className={`size-4 ${tone}`} />
            {text}
          </li>
        ))}
      </motion.ul>
    </div>
  );
}
