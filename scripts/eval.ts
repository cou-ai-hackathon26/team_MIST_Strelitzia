// Sentinel evaluation: replays each demo scenario against the live brain and scores the verdicts.
// Usage: bun run eval [--runs N] [--scenario <id>]      (needs a running brain + lab; reads the root .env)
// Per run: full reset (recreates the lab servers, switches CVE scanning off) → wait until every lab server reports a
// fresh inventory → allow CVE scanning (which starts a scan) → scan until the scenario's findings are complete →
// compare status/priority per host with scripts/eval-scenarios.json, and check every finding has an investigation
// (≥1 step) and, unless not_affected, a non-empty remediation plan. Exit 1 on any mismatch. Resets at the end, which
// leaves CVE scanning off again.
import type { Finding, HostSummary, StatusResponse } from "@prohori/shared";
import expectations from "./eval-scenarios.json";

const BRAIN = (process.env.BRAIN_URL ?? `http://127.0.0.1:${process.env.BRAIN_PORT ?? 4400}`).replace(/\/$/, "");
const TOKEN = process.env.BRAIN_API_TOKEN ?? "";
const argv = process.argv.slice(2);
const argOf = (k: string) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
const runsOverride = argOf("--runs") ? Number(argOf("--runs")) : null;
const only = argOf("--scenario");
const SCAN_DEADLINE_MS = 10 * 60_000;

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BRAIN}/api${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, "content-type": "application/json", "X-Prohori-Actor": "eval" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`${method} ${path} → HTTP ${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}
const sleep = (ms: number) => Bun.sleep(ms);
const status = () => api<StatusResponse>("GET", "/status");
const secs = (ms: number) => `${(ms / 1000).toFixed(1)}s`;

async function waitUntil(what: string, ms: number, fn: () => Promise<boolean>) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (await fn()) return;
    await sleep(2000);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function waitIdle() {
  await waitUntil("the running scan to finish", SCAN_DEADLINE_MS, async () => !(await status()).scan.running);
}

/** Every host online, assessable, and with an inventory received after `sinceMs` (i.e. from the recreated server). */
async function waitHostsReady(sinceMs: number) {
  await waitUntil("the lab servers to come back with a fresh inventory", 4 * 60_000, async () => {
    const hs = (await status()).hosts;
    return hs.length > 0 && hs.every((h) => h.status === "online"
      && (!h.health || (h.health.state === "ok" && !!h.health.lastInventoryAt && Date.parse(h.health.lastInventoryAt) >= sinceMs)));
  });
}

async function resetAll() {
  const t = Date.now();
  // Full reset: cancels running work, wipes findings/actions/reports, recreates the lab servers, scanning off
  const r = await api<{ restoring: string[]; failed: string[] }>("POST", "/demo/reset", {});
  if (r.failed.length) console.warn(`  reset problems: ${r.failed.join("; ")}`);
  await sleep(5000); // the containers are recreated in the background; let the old daemons drop first
  await waitHostsReady(t);
  await waitIdle();
  return r.restoring;
}

interface Expect { host: string; status: string; priority: string }
interface RunResult {
  scenario: string; run: number; ok: boolean; latencyMs: number; scanMs: number | null; scans: number;
  rows: { host: string; cve: string; status: string; priority: string; expected: string; ok: boolean; steps: number; plan: number; guardrail: string | null; note: string }[];
}

async function runScenario(id: string, cves: string[], expect: Expect[], run: number): Promise<RunResult> {
  const restoring = await resetAll();
  console.log(`\n[${id} #${run}] reset done${restoring.length ? ` (${restoring.join("; ")})` : ""}; allowing CVE scanning for ${cves.join(", ")}`);
  const hosts = await api<HostSummary[]>("GET", "/hosts");
  const nameOf = new Map(hosts.map((h) => [h.id, h.name]));
  await api("POST", "/demo/inject", { scenarioId: id }); // scenario bookkeeping only; scans are gated by the setting below
  let seen = (await status()).scan.lastFinishedAt;
  const t0 = Date.now();
  await api("PUT", "/settings", { cveScanEnabled: true }); // "Allow CVE Scan": the brain starts a scan right away
  let scans = 0;
  let scanMs: number | null = null;
  let findings: Finding[] = [];
  const complete = (fs: Finding[]) => expect.every((e) => cves.every((c) => fs.some((f) => f.cveId === c && nameOf.get(f.hostId) === e.host)));
  while (Date.now() - t0 < SCAN_DEADLINE_MS) {
    await waitIdle();
    if ((await status()).scan.lastFinishedAt === seen) {
      // no scan has finished since we last looked (the one started by enabling may not have begun yet): run one
      const r = await api<{ started: boolean }>("POST", "/scan");
      if (!r.started) { await sleep(2000); continue; }
      await waitUntil("scan", SCAN_DEADLINE_MS, async () => { const x = (await status()).scan; return !x.running && x.lastFinishedAt !== seen; });
    }
    scans++;
    const s = (await status()).scan;
    seen = s.lastFinishedAt;
    scanMs = s.lastStartedAt && s.lastFinishedAt ? Date.parse(s.lastFinishedAt) - Date.parse(s.lastStartedAt) : null;
    findings = (await api<Finding[]>("GET", "/findings")).filter((f) => cves.includes(f.cveId));
    if (s.lastResult?.error) console.warn(`  scan error: ${s.lastResult.error}`);
    if (complete(findings)) break;
    console.log(`  scan ${scans} finished without all expected findings (${findings.length}); retrying`);
  }
  const latencyMs = Date.now() - t0;
  const rows: RunResult["rows"] = [];
  for (const e of expect) {
    for (const c of cves) {
      const f = findings.find((x) => x.cveId === c && nameOf.get(x.hostId) === e.host);
      const inv = f?.investigation;
      const notes: string[] = [];
      if (!f) notes.push("no finding");
      else {
        if (f.status !== e.status) notes.push(`status ${f.status}`);
        if (f.priority !== e.priority) notes.push(`priority ${f.priority}`);
        if (!inv || !inv.steps?.length) notes.push("no investigation steps");
        if (f.status !== "not_affected" && !(inv?.remediationPlan?.length)) notes.push("empty remediation plan");
      }
      rows.push({
        host: e.host, cve: c, status: f?.status ?? "-", priority: f?.priority ?? "-", expected: `${e.status}/${e.priority}`,
        ok: notes.length === 0, steps: inv?.steps?.length ?? 0, plan: inv?.remediationPlan?.length ?? 0, guardrail: inv?.guardrail ?? null, note: notes.join(", "),
      });
    }
  }
  for (const f of findings) {
    const h = nameOf.get(f.hostId) ?? f.hostId;
    if (!expect.some((e) => e.host === h) && f.status !== "not_affected") {
      rows.push({ host: h, cve: f.cveId, status: f.status, priority: f.priority, expected: "(no finding)", ok: false, steps: f.investigation?.steps?.length ?? 0, plan: 0, guardrail: null, note: "unexpected finding" });
    }
  }
  const ok = rows.every((r) => r.ok);
  console.log(`  ${ok ? "PASS" : "FAIL"} in ${secs(latencyMs)} (scan allowed → verdicts; ${scans} scan(s), last scan ${scanMs !== null ? secs(scanMs) : "?"})`);
  for (const r of rows) {
    console.log(`  ${r.ok ? "ok  " : "FAIL"} ${r.host.padEnd(14)} ${r.cve.padEnd(16)} ${`${r.status}/${r.priority}`.padEnd(32)} expected ${r.expected.padEnd(32)} steps=${r.steps} plan=${r.plan}${r.note ? `  ← ${r.note}` : ""}${r.guardrail ? `\n         guardrail: ${r.guardrail}` : ""}`);
  }
  return { scenario: id, run, ok, latencyMs, scanMs, scans, rows };
}

async function main() {
  if (!TOKEN) throw new Error("BRAIN_API_TOKEN missing (run via `bun run eval` so the root .env is loaded)");
  // daemons reconnect with backoff after a brain restart: give them a moment
  await waitUntil("hosts online", 90_000, async () => (await status()).hosts.every((h) => h.status === "online")).catch(() => {});
  const st = await status();
  const offline = st.hosts.filter((h) => h.status !== "online");
  console.log(`Sentinel eval against ${BRAIN}: hosts ${st.hosts.map((h) => `${h.name}(${h.status})`).join(", ")}`);
  if (offline.length) console.warn(`WARNING: offline hosts: ${offline.map((h) => h.name).join(", ")}`);
  const known = new Map(st.demo.scenarios.map((s) => [s.id, s]));
  const results: RunResult[] = [];
  try {
    for (const sc of expectations.scenarios) {
      if (only && sc.id !== only) continue;
      const def = known.get(sc.id);
      if (!def) { console.error(`scenario ${sc.id} is not configured in DEMO_SCENARIOS`); results.push({ scenario: sc.id, run: 0, ok: false, latencyMs: 0, scanMs: null, scans: 0, rows: [] }); continue; }
      const runs = runsOverride ?? sc.runs;
      for (let i = 1; i <= runs; i++) {
        try {
          results.push(await runScenario(sc.id, def.cveIds, sc.expect, i));
        } catch (e) {
          console.error(`  run failed: ${(e as Error).message}`);
          results.push({ scenario: sc.id, run: i, ok: false, latencyMs: 0, scanMs: null, scans: 0, rows: [] });
        }
      }
    }
  } finally {
    console.log("\nresetting the demo…");
    try { await resetAll(); } catch (e) { console.error(`final reset failed: ${(e as Error).message}`); }
  }
  console.log("\n=== score ===");
  console.log("scenario      run  result  checks   allow→verdict   last scan  scans");
  for (const r of results) {
    const pass = r.rows.filter((x) => x.ok).length;
    console.log(`${r.scenario.padEnd(13)} ${String(r.run).padEnd(4)} ${(r.ok ? "PASS" : "FAIL").padEnd(7)} ${`${pass}/${r.rows.length}`.padEnd(8)} ${secs(r.latencyMs).padEnd(15)} ${(r.scanMs !== null ? secs(r.scanMs) : "-").padEnd(10)} ${r.scans}`);
  }
  const byScenario = new Map<string, RunResult[]>();
  for (const r of results) byScenario.set(r.scenario, [...(byScenario.get(r.scenario) ?? []), r]);
  for (const [s, rs] of byScenario) console.log(`${s}: ${rs.filter((r) => r.ok).length}/${rs.length} runs passed`);
  const failed = results.some((r) => !r.ok);
  console.log(failed ? "\nEVAL FAILED" : "\nEVAL PASSED");
  process.exit(failed ? 1 : 0);
}

await main();
