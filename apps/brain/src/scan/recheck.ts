// Targeted re-check after an approved action (or its rollback) on ONE host: re-assess only that host's findings
// right after the daemon's refreshed inventory arrives — no OSV sweep, no triage, and independent of the
// "Allow CVE Scan" gate (it only re-checks findings that already exist). Same investigator, guardrails and planner
// as a scan; the fix status comes from fixStatusFor (correct without scan matches, e.g. after an upgrade).
import type { Finding, ThreatProfile } from "@prohori/shared";
import {
  audit, getFinding, getFindingByKey, getInventory, getProfile, listActions, listFindings, listJudgments, nowIso, saveAction, saveFinding,
} from "../db";
import { closeObsoleteProposals } from "../actions";
import { kevEntry } from "../vuln/kev";
import { getVuln, upstreamRanges, type OsvVuln } from "../vuln/osv";
import type { VersionRange } from "../vuln/versions";
import { bestSeverity, buildFinding, evidenceHash, loadHosts, priorityLabel, sourcesOf, statusLabel, type Candidate, type ScanHost } from "./engine";
import { evidenceFor } from "./judge";
import { investigateHost } from "./investigate";
import { mitigationsFromPlan, planRemediation } from "./plan";
import { fallbackProfile } from "./profile";
import { proposeFixesFor } from "./workflow";
import { mapPool } from "./util";

const INVENTORY_WAIT_MS = 12_000;

let generation = 0;
/** host → the re-check running/queued for it (one at a time per host; a new request coalesces into the queued one) */
const chains = new Map<string, Promise<void>>();
const queued = new Map<string, { reasons: string[]; since: number }>();

/** Environment reset: in-flight re-checks stop writing; queued ones are dropped. */
export function cancelRechecks() {
  generation++;
  queued.clear();
}

/**
 * Ask for a re-check of `hostId` (called when a daemon reports an action result). `sinceMs` = when the result
 * arrived; the re-check waits for an inventory collected after it, so it sees the new firewall/package state.
 */
export function requestRecheck(hostId: string, reason: string, sinceMs = Date.now()) {
  const q = queued.get(hostId);
  if (q) { q.reasons.push(reason); q.since = Math.max(q.since, sinceMs); return; }
  queued.set(hostId, { reasons: [reason], since: sinceMs });
  const prev = chains.get(hostId) ?? Promise.resolve();
  const next = prev.then(async () => {
    const job = queued.get(hostId);
    queued.delete(hostId);
    if (!job) return;
    try { await recheckHost(hostId, job.reasons.join("; "), job.since); }
    catch (e) {
      console.error(`[recheck] ${hostId} failed`, e);
      audit("error", `Re-check of ${hostId} failed: ${(e as Error).message}`, { hostId });
      settleActions(hostId, Date.now()); // don't leave the action "re-assessing" forever; the next scan re-checks it
    }
  });
  chains.set(hostId, next);
  void next.finally(() => { if (chains.get(hostId) === next) chains.delete(hostId); });
}

async function waitForInventory(hostId: string, sinceMs: number): Promise<boolean> {
  const deadline = Date.now() + INVENTORY_WAIT_MS;
  while (Date.now() < deadline) {
    const inv = getInventory(hostId);
    if (inv && Date.parse(inv.collectedAt) >= sinceMs - 1000) return true;
    await Bun.sleep(400);
  }
  return false;
}

/** The judgment a CVE was tracked from (its advisory carries the ranges/fix facts OSV may not have). */
function trackedAdvisory(cve: string) {
  return listJudgments(200).find((j) => j.tracked?.cveId === cve)?.advisory ?? null;
}

async function candidateFor(f: Finding): Promise<{ c: Candidate; ranges: VersionRange[]; upstreamFixed: string[] }> {
  const cve = f.cveId;
  const [cveRec, ubuntu, debian] = await Promise.all([getVuln(cve), getVuln(`UBUNTU-${cve}`), getVuln(`DEBIAN-${cve}`)].map((p) => p.catch(() => null))) as (OsvVuln | null)[];
  const adv = trackedAdvisory(cve);
  const recRanges = upstreamRanges(cveRec);
  const ranges: VersionRange[] = recRanges.length ? recRanges : (adv?.affectedRanges ?? []);
  const upstreamFixed = adv?.fixedVersions ?? [];
  const ke = kevEntry(cve);
  const sev = bestSeverity([ubuntu, debian, cveRec]);
  const c: Candidate = {
    cve,
    sourcePkgs: f.package ? [f.package.name] : [],
    aliases: f.aliases,
    title: f.title,
    summary: cveRec?.summary ?? ubuntu?.summary ?? "",
    details: (cveRec?.details ?? ubuntu?.details ?? debian?.details ?? "").slice(0, 4000),
    kev: !!ke,
    kevInfo: ke,
    cvss: f.cvss ?? (sev.vector ? (sev.score !== null ? `${sev.score} ${sev.vector}` : sev.vector) : null),
    cvssScore: sev.score,
    severityLabel: sev.label,
    upstreamRanges: ranges,
    cveRecord: cveRec,
    distroRecords: { UBUNTU: ubuntu, DEBIAN: debian },
    textOnly: adv ? { product: adv.product, sourcePackageGuess: adv.sourcePackageGuess, affectedRanges: ranges, fixedVersions: adv.fixedVersions, conditions: adv.conditions } : null,
    reason: "re-check after an action",
    triage: f.investigation?.triage ?? { decidedBy: "rule", reason: "re-check of an existing finding" },
    profile: null,
  };
  return { c, ranges, upstreamFixed };
}

/** Actions on this host waiting for a re-check whose result predates `beforeMs` are settled ("done"). */
function settleActions(hostId: string, beforeMs: number) {
  for (const a of listActions({ hostId })) {
    if (a.progress?.phase !== "rechecking") continue;
    if (Date.parse(a.progress.resultAt ?? a.progress.since) <= beforeMs) { a.progress = { ...a.progress, phase: "done", since: nowIso() }; saveAction(a); }
  }
}

export async function recheckHost(hostId: string, reason: string, sinceMs: number): Promise<void> {
  const gen = generation;
  const live = () => gen === generation;
  const startedAt = Date.now();
  const fresh = await waitForInventory(hostId, sinceMs);
  if (!live()) return;
  const host: ScanHost | undefined = loadHosts().find((h) => h.id === hostId);
  if (!host) return;
  const findings = listFindings({ hostId });
  const notes: string[] = [];
  if (!fresh) notes.push("no refreshed inventory within 12 s; re-checked against the latest stored inventory");

  const results = await mapPool(findings, 3, async (f) => {
    if (!live()) return null;
    const src = f.package?.name ?? null;
    if (!src || !sourcesOf(host.inv).has(src)) return { f, removed: true as const };
    const { c, ranges, upstreamFixed } = await candidateFor(f);
    if (!live()) return null;
    const profile: ThreatProfile = getProfile(c.cve) ?? fallbackProfile(c);
    c.profile = profile;
    const { e } = evidenceFor(host, src, c, ranges, upstreamFixed);
    const prev = getFindingByKey(hostId, c.cve);
    if (prev && prev.finding.investigation && prev.evidenceHash === evidenceHash(e, profile.generatedAt)) return { f, unchanged: true as const };
    const k = await investigateHost(`recheck-${hostId}-${c.cve}-${startedAt}`, c, e, profile);
    if (!live()) return null;
    if (k.status !== "not_affected") {
      const { plan, error } = await planRemediation(`recheck-${hostId}-${c.cve}-${startedAt}-plan`, c, k, profile);
      if (!live()) return null;
      if (error) notes.push(`planner failed for ${c.cve}, deterministic plan used`);
      k.investigation.remediationPlan = plan;
      k.mitigations = mitigationsFromPlan(plan);
    }
    return { f, c, k };
  });
  if (!live()) return;

  // write (synchronous from here on: a reset cannot interleave)
  const now = nowIso();
  const changes: string[] = [];
  let proposed = 0;
  for (const r of results) {
    if (!r || "unchanged" in r) continue;
    const prevF = getFinding(r.f.id);
    if (!prevF) continue; // deleted meanwhile (reset / scenario reset)
    if ("removed" in r) {
      if (prevF.status === "not_affected") continue;
      Object.assign(prevF, {
        status: "not_affected", priority: "info", confidence: "high", updatedAt: now,
        rationale: `${prevF.package?.name ?? "The affected package"} is no longer installed on ${host.name}.`, mitigations: ["No action needed."],
      });
      saveFinding(prevF, "removed");
      changes.push(`${prevF.cveId}: ${statusLabel(r.f.status)} → Not Affected (package removed)`);
      audit("finding_changed", `${host.name} · ${prevF.cveId}: ${statusLabel(r.f.status)} → Not Affected (package removed)`, { hostId, cveId: prevF.cveId, data: { findingId: prevF.id, from: r.f.status } });
      continue;
    }
    const { c, k } = r;
    const f = buildFinding(c, k, prevF, now);
    saveFinding(f, k.evidenceHash);
    if (prevF.status !== f.status || prevF.priority !== f.priority) {
      changes.push(`${c.cve}: ${statusLabel(prevF.status)} → ${statusLabel(f.status)}`);
      if (f.status !== "not_affected") {
        audit("vulnerable_detected", `${host.name} assessed ${statusLabel(f.status)} for ${c.cve}: ${f.status === "exposed" ? "reachable from the network" : "no network path to the vulnerable component"}.`, {
          hostId, cveId: c.cve, data: { findingId: f.id, status: f.status, priority: f.priority, from: prevF.status },
        });
      }
      audit("finding_changed", `${host.name} · ${c.cve}: ${statusLabel(prevF.status)} → ${statusLabel(f.status)} (${priorityLabel(f.priority)})`, { hostId, cveId: c.cve, data: { findingId: f.id, from: prevF.status } });
    }
    if (f.status === "exposed") proposed += proposeFixesFor(f, notes);
  }
  const closed = closeObsoleteProposals((id) => getFinding(id)?.status ?? null);

  settleActions(hostId, startedAt);
  const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
  audit("scan_finished", `Re-checked ${host.name} in ${secs}s (${reason}): ${findings.length} finding(s); ${changes.length ? changes.join(", ") : "no status changes"}${proposed ? `; ${proposed} fix(es) proposed` : ""}${closed ? `; ${closed} obsolete proposal(s) closed` : ""}`, {
    hostId, data: { recheck: true, reason, changes, proposed, closed, notes },
  });
}
