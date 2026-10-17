import type { NextConfig } from "next";

// A static showcase: no rewrites, no proxies, no request-time rendering. The gateway's live view is its
// own GUI at 127.0.0.1:8787, which refuses cross-origin requests by design (see /run-it).
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
};

export default nextConfig;
