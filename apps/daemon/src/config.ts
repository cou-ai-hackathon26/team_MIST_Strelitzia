import { readFileSync } from "node:fs";

export const DAEMON_VERSION = "0.1.0";

export interface DaemonConfig {
  brainUrl: string;
  hostId: string;
  token: string;
  tier2: boolean;
  osqueryi: string;
  stateDir: string;
}

const KEYS = ["PROHORI_BRAIN_URL", "PROHORI_HOST_ID", "PROHORI_TOKEN", "PROHORI_TIER2", "OSQUERYI", "PROHORI_STATE_DIR"] as const;

/** Config: optional JSON file (PROHORI_CONFIG, same keys as the env vars), overridden by env vars. */
export function loadConfig(): DaemonConfig {
  const merged: Record<string, string> = {};
  const file = process.env.PROHORI_CONFIG;
  if (file) {
    const json = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
    for (const k of KEYS) if (json[k] !== undefined && json[k] !== null) merged[k] = String(json[k]);
  }
  for (const k of KEYS) {
    const v = process.env[k];
    if (v !== undefined && v !== "") merged[k] = v;
  }
  const missing = ["PROHORI_BRAIN_URL", "PROHORI_HOST_ID", "PROHORI_TOKEN"].filter((k) => !merged[k]);
  if (missing.length) throw new Error(`missing config: ${missing.join(", ")} (env or PROHORI_CONFIG file)`);
  return {
    brainUrl: merged.PROHORI_BRAIN_URL!,
    hostId: merged.PROHORI_HOST_ID!,
    token: merged.PROHORI_TOKEN!,
    tier2: (merged.PROHORI_TIER2 ?? "false").toLowerCase() === "true",
    osqueryi: merged.OSQUERYI ?? "osqueryi",
    stateDir: merged.PROHORI_STATE_DIR ?? "/var/lib/prohori",
  };
}
