import type { NextConfig } from "next";
import { existsSync } from "node:fs";
import path from "node:path";

// Load the repo-root .env (BRAIN_URL, BRAIN_API_TOKEN, ADMIN_PASSWORD, SESSION_SECRET).
// process.loadEnvFile never overrides variables already set in the environment,
// so `BRAIN_URL=http://127.0.0.1:4100 bun run dev` still wins.
const rootEnv = path.resolve(process.cwd(), "../../.env");
if (existsSync(rootEnv)) {
  try {
    process.loadEnvFile(rootEnv);
  } catch {
    /* ignore malformed env */
  }
}

const nextConfig: NextConfig = {
  transpilePackages: ["@prohori/shared"],
  // Monorepo: packages/shared lives outside apps/web.
  turbopack: { root: path.resolve(process.cwd(), "../..") },
  // Compression can buffer the SSE chat stream; this is a local ops dashboard, so turn it off.
  compress: false,
  poweredByHeader: false,
  devIndicators: false,
  agentRules: false,
  // Allow opening the dev server via 127.0.0.1 (Next blocks cross-origin dev resources by default).
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  async redirects() {
    return [{ source: "/audit", destination: "/events", permanent: false }];
  },
};

export default nextConfig;
