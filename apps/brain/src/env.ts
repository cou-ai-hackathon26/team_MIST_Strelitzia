import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const APP_ROOT = resolve(import.meta.dir, "..");

function req(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") throw new Error(`Missing env ${name}`);
  return v;
}

const dbPath = resolve(APP_ROOT, process.env.BRAIN_DB_PATH ?? "./data/prohori.db");
mkdirSync(dirname(dbPath), { recursive: true });

export const env = {
  port: Number(process.env.BRAIN_PORT ?? 4000),
  apiToken: req("BRAIN_API_TOKEN"),
  dbPath,
  mastraDbPath: resolve(dirname(dbPath), "mastra.db"),
  seedHosts: (process.env.SEED_HOSTS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [id, name, token] = s.split(":");
      return { id: id!, name: name ?? id!, token: token ?? "" };
    })
    .filter((h) => h.id && h.token),
  replayHold: (process.env.DEMO_REPLAY_HOLD ?? "CVE-2026-109618,CVE-2026-109619")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean),
  smtpHost: process.env.SMTP_HOST ?? "127.0.0.1",
  smtpPort: Number(process.env.SMTP_PORT ?? 1025),
  reportFrom: process.env.REPORT_FROM ?? "prohori@localhost",
  defaultReportEmails: (process.env.DEFAULT_REPORT_EMAILS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  llm: {
    baseURL: req("LLM_BASE_URL"),
    apiKey: req("OPENCODE_API_KEY"),
    model: req("LLM_MODEL"),
    userAgent: process.env.LLM_USER_AGENT ?? "prohori/0.1",
  },
  /** Public URL daemons use to reach the brain (for enroll install command). */
  publicUrl: process.env.BRAIN_PUBLIC_URL ?? `http://127.0.0.1:${process.env.BRAIN_PORT ?? 4000}`,
  firstScanDelayMs: Number(process.env.FIRST_SCAN_DELAY_MS ?? 20_000),
};
