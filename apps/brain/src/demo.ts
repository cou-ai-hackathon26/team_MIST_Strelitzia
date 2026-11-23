// Demo replay: embargoed disclosures (env DEMO_SCENARIOS + DEMO_REPLAY_HOLD) that can be released/reset per scenario.
import type { DemoScenario, Finding } from "@prohori/shared";
import {
  audit, deleteAction, deleteFindingsForCves, deleteReport, holdState, listActions, saveSettings, wipeOperationalState, listFindings, listReports, setHold,
} from "./db";
import { resolve } from "node:path";
import { env } from "./env";
import { describeAction, HttpError, rollbackAction } from "./actions";

export function scenarios(): DemoScenario[] {
  const injected = new Set(holdState().injected);
  return env.scenarios.map((s) => ({ ...s, state: s.cveIds.every((c) => injected.has(c)) ? "released" : "embargoed" }));
}

function scenarioOrThrow(id: string) {
  const s = env.scenarios.find((x) => x.id === id);
  if (!s) throw new HttpError(404, `unknown scenario "${id}"; known: ${env.scenarios.map((x) => x.id).join(", ") || "none"}`);
  return s;
}

const who = (actor: string) => (actor === "unknown" ? "Operator" : actor);

export function inject(actor: string, b: { scenarioId?: string; cveIds?: string[] }): { injected: string[] } {
  const known = new Set([...env.replayHold, ...holdState().held]);
  let ids: string[];
  let label: string;
  if (b.scenarioId) {
    const s = scenarioOrThrow(b.scenarioId);
    ids = s.cveIds;
    label = `${s.title} (${ids.join(", ")})`;
  } else if (b.cveIds?.length) {
    ids = b.cveIds.map((x) => String(x).toUpperCase()).filter((x) => known.has(x));
    label = ids.join(", ");
  } else {
    ids = [...known];
    label = env.scenarios.length ? env.scenarios.map((s) => s.title).join(", ") : ids.join(", ");
  }
  setHold(ids, "injected");
  audit("demo_inject", `${who(actor)} replayed the disclosure of ${label}; Sentinel will assess it on the next scheduled scan`, { actor, data: { cveIds: ids, scenarioId: b.scenarioId ?? null } });
  return { injected: holdState().injected };
}

const REVERTIBLE = new Set(["upgrade_packages", "firewall_port", "nginx_block_multipart", "set_php_directive", "set_config_directive"]);

/** Reset one scenario (or everything): roll back its still-applied actions, re-embargo, clear findings/reports/proposals. */
const COMPOSE = resolve(import.meta.dir, "../../../infra/docker-compose.yml");

/** Full reset (no scenario): wipe everything operational and recreate the lab containers; caches (OSV, KEV, triage, threat profiles) are kept. */
function fullReset(actor: string): { ok: true; restoring: string[]; failed: string[] } {
  setHold(env.replayHold, "held");
  saveSettings({ cveScanEnabled: false });
  wipeOperationalState();
  audit("demo_inject", `${who(actor)} reset the demonstration environment: cleared all findings, reports, approvals, chats and the event log; recreating the lab servers (scan caches kept)`, { actor, data: { cveIds: env.replayHold, full: true } });
  const proc = Bun.spawn(["docker", "compose", "-f", COMPOSE, "up", "-d", "--force-recreate", "target-a", "target-b", "target-c", "target-d"], { stdout: "ignore", stderr: "pipe" });
  proc.exited.then(async (code) => {
    if (code !== 0) audit("demo_inject", `Lab server recreation failed (exit ${code}): ${(await new Response(proc.stderr).text()).slice(-300)}`, { actor });
  });
  return { ok: true, restoring: ["lab servers recreating from clean images"], failed: [] };
}

export function reset(actor: string, b: { scenarioId?: string }): { ok: true; restoring: string[]; failed: string[] } {
  if (!b.scenarioId) return fullReset(actor);
  const scoped = b.scenarioId ? scenarioOrThrow(b.scenarioId) : null;
  const ids = scoped ? scoped.cveIds : env.replayHold;
  const scenarioFindingIds = new Set(listFindings().filter((f: Finding) => ids.includes(f.cveId)).map((f) => f.id));
  // 1) put the servers back: roll back state-changing actions that are still applied (newest first).
  //    Scenario reset: only actions linked to that scenario's findings. Full reset: every applied action.
  const restoring: string[] = [];
  const failed: string[] = [];
  const keep = new Set<string>();
  for (const a of listActions({ state: "applied" })) {
    if (!REVERTIBLE.has(a.type) || a.rolledBackBy) continue;
    if (scoped && !(a.findingId && (scenarioFindingIds.has(a.findingId) || ids.some((c) => a.findingId!.endsWith(`_${c}`))))) continue;
    try {
      rollbackAction(a.id, { actor, note: `demo reset${scoped ? ` (${scoped.title})` : ""}: restoring the server` });
      restoring.push(describeAction(a));
      keep.add(a.id);
    } catch (e) {
      failed.push(`${describeAction(a)}: ${(e as Error).message}`);
    }
  }
  // 2) re-hold the CVEs and clear their findings / reports / open proposals (keep records being rolled back)
  setHold(ids, "held");
  const findingIds = new Set(deleteFindingsForCves(ids));
  let reports = 0, actions = 0;
  for (const r of listReports()) {
    if (r.findingIds.some((id) => findingIds.has(id))) { deleteReport(r.id); reports++; }
  }
  for (const a of listActions()) {
    if (keep.has(a.id)) continue;
    if (a.findingId && findingIds.has(a.findingId) && !["applied", "running", "approved"].includes(a.state)) { deleteAction(a.id); actions++; }
  }
  audit("demo_inject", `${who(actor)} reset the demonstration environment${scoped ? ` for ${scoped.title}` : ""}: re-embargoed ${ids.join(", ")}; cleared ${findingIds.size} findings, ${reports} reports, ${actions} open proposals` +
    (restoring.length ? `; rolling back ${restoring.length} applied remediation(s): ${restoring.join("; ")}` : "") +
    (failed.length ? `; could not roll back: ${failed.join("; ")}` : ""), {
    actor, data: { cveIds: ids, scenarioId: scoped?.id ?? null, findings: findingIds.size, reports, actions, restoring, failed },
  });
  return { ok: true, restoring, failed };
}
