import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const APP_ROOT = resolve(import.meta.dir, "..");

function req(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") throw new Error(`Missing env ${name}`);
  return v;
}

const csvIds = (s: string) => s.split(",").map((x) => x.trim().toUpperCase()).filter(Boolean);

function parseScenarios(raw: string): { id: string; title: string; cveIds: string[] }[] {
  const out: { id: string; title: string; cveIds: string[] }[] = [];
  for (const part of raw.split(";").map((x) => x.trim()).filter(Boolean)) {
    const a = part.indexOf(":");
    const b = part.lastIndexOf(":");
    if (a < 0 || b <= a) { console.warn(`[env] DEMO_SCENARIOS: ignoring malformed entry "${part}"`); continue; }
    const id = part.slice(0, a).trim();
    const title = part.slice(a + 1, b).trim() || id;
    const cveIds = csvIds(part.slice(b + 1));
    if (!/^[a-z0-9][a-z0-9_-]*$/i.test(id) || !cveIds.length) { console.warn(`[env] DEMO_SCENARIOS: ignoring malformed entry "${part}"`); continue; }
    out.push({ id, title, cveIds });
  }
  return out;
}
const scenarios = parseScenarios(process.env.DEMO_SCENARIOS ?? "");

const dbPath = resolve(APP_ROOT, process.env.BRAIN_DB_PATH ?? "./data/prohori.db");
mkdirSync(dirname(dbPath), { recursive: true });

export const env = {
  port: Number(process.env.BRAIN_PORT ?? 4400),
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
  /** Replayable disclosures: DEMO_SCENARIOS="id:Title:CVE,CVE;id:Title:CVE". */
  scenarios,
  /** Every embargoed CVE: DEMO_REPLAY_HOLD ∪ all scenario CVEs. */
  replayHold: [...new Set([...csvIds(process.env.DEMO_REPLAY_HOLD ?? ""), ...scenarios.flatMap((s) => s.cveIds)])],
  /** Permanently suppressed CVEs (never scanned/reported): DEMO_IGNORE_CVES="CVE-…,CVE-…". */
  ignoreCves: csvIds(process.env.DEMO_IGNORE_CVES ?? ""),
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
  publicUrl: process.env.BRAIN_PUBLIC_URL ?? `http://127.0.0.1:${process.env.BRAIN_PORT ?? 4400}`,
  firstScanDelayMs: Number(process.env.FIRST_SCAN_DELAY_MS ?? 20_000),
  /** Parallel host investigations (each is a chain of LLM calls) in scans, judgments and re-checks. */
  investigationConcurrency: Math.max(1, Math.min(16, Number(process.env.SCAN_CONCURRENCY ?? 6) || 6)),
};
