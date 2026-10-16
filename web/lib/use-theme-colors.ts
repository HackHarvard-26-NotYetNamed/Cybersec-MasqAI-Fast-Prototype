"use client";

import { useSyncExternalStore } from "react";

// SVG presentation attributes (what Recharts writes) can't use var(), so charts read the resolved
// token values and re-read them when the theme class on <html> changes.
const TOKENS = ["series-raw", "series-masq", "muted-foreground", "foreground", "border", "muted", "popover"] as const;
export type ThemeColors = Record<(typeof TOKENS)[number], string>;

const DARK_FALLBACK = "#d95926|#3987e5|#a2abb5|#e8eaed|#262c35|#1a1e24|#181c22";

function subscribe(onChange: () => void) {
  const observer = new MutationObserver(onChange);
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
  return () => observer.disconnect();
}

function snapshot() {
  const style = getComputedStyle(document.documentElement);
  return TOKENS.map((t) => style.getPropertyValue(`--${t}`).trim()).join("|");
}

export function useThemeColors(): ThemeColors {
  const joined = useSyncExternalStore(subscribe, snapshot, () => DARK_FALLBACK);
  const values = joined.split("|");
  return Object.fromEntries(TOKENS.map((t, i) => [t, values[i]])) as ThemeColors;
}
