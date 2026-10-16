import type { NextConfig } from "next";

// /live may read the local gateway, but only from `npm run dev` with NEXT_PUBLIC_LIVE_MODE=true.
// The gateway refuses cross-origin browser requests, so the dev server proxies three read-only GUI
// endpoints and the browser sees them as same-origin. The gateway still applies its own Host,
// Origin and Sec-Fetch-Site checks to every proxied request. Production builds (Vercel) never get
// these rewrites.
const LIVE = process.env.NEXT_PUBLIC_LIVE_MODE === "true" && process.env.NODE_ENV !== "production";
const GATEWAY = "http://127.0.0.1:8787";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    if (!LIVE) return [];
    return ["state", "security", "events"].map((name) => ({
      source: `/gateway/api/${name}`,
      destination: `${GATEWAY}/api/${name}`,
    }));
  },
};

export default nextConfig;
