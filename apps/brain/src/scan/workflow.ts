// The scan as a Mastra workflow with fixed, deterministic step order. Sentinel (AI) runs inside triage,
// advisory analysis, investigation, remediation planning and report; code keeps the hard guarantees (matching,
// distro verdict, guardrails, action validation). Heavy data stays in an in-memory ScanContext keyed by scanId;
// steps pass only { scanId } so workflow snapshots stay small.
import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";
import { env } from "../env";
import type { ActionType, Finding } from "@prohori/shared";
import { audit, getFindingByKey, getSettings, listFindings, newId, nowIso, saveFinding, saveReport, getFinding } from "../db";
import { sendReportEmail } from "../mailer";
import { closeObsoleteProposals, hasEquivalentAction, markRechecked, proposeAction } from "../actions";
import { extractAdvisory, writeReport } from "./ai";
import {
  buildCandidates, buildEvidence, buildFinding, evidenceHash, heldSet, priorityLabel, statusLabel, loadHosts, matchedCves, needsTextPath, osvMatch,
  sourcesOf, type ScanContext,
} from "./engine";
import { triage } from "./triage";
import { profileFor } from "./profile";
import { investigateHost } from "./investigate";
import { mitigationsFromPlan, planRemediation } from "./plan";
import { mapPool } from "./util";


export const scanContexts = new Map<string, ScanContext>();
/** finished scans whose report is still being written in the background (a reset must cancel these too) */
export const backgroundReports = new Set<ScanContext>();
const IO = z.object({ scanId: z.string() });
export class ScanCancelled extends Error {
  constructor() { super("scan cancelled by an environment reset"); this.name = "ScanCancelled"; }
}
/** Throws if a reset cancelled this scan. DB writes are synchronous, so checking at step start and after every await
 *  guarantees a cancelled scan never writes findings, reports, proposals, emails or audit entries. */
export function assertLive(ctx: ScanContext) {
  if (ctx.cancelled) throw new ScanCancelled();
}
const ctxOf = (scanId: string) => {
  const c = scanContexts.get(scanId);
  if (!c) throw new Error(`scan context ${scanId} missing`);
  assertLive(c);
  return c;
};

const loadInventory = createStep({
  id: "load-inventory",
  description: "Load the latest inventory snapshot of every host",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    ctx.hosts = loadHosts();
    return inputData;
  },
});

const osvMatchStep = createStep({
  id: "osv-match",
  description: "Query OSV (distro ecosystem, source package + installed version) → raw matches per host",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    await osvMatch(ctxOf(inputData.scanId));
    return inputData;
  },
});

const triageStep = createStep({
  id: "triage",
  description: "Sentinel triage of every raw-matched CVE (floor rule: KEV / distro critical → always), cached per CVE",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    const matched = matchedCves(ctx);
    const chosen = await triage(ctx, matched);
    // keep re-evaluating CVEs that still have open findings, so they can resolve
    const held = heldSet();
    for (const f of listFindings()) {
      if (f.status === "not_affected" || chosen.has(f.cveId) || held.has(f.cveId)) continue;
      chosen.set(f.cveId, { sources: new Set(f.package ? [f.package.name] : []), decidedBy: f.investigation?.triage.decidedBy ?? "rule", reason: f.investigation?.triage.reason ?? "re-check of an open finding" });
    }
    await buildCandidates(ctx, chosen);
    return inputData;
  },
});

const extractAdvisories = createStep({
  id: "extract-advisories",
  description: "AI (no tools): parse advisory text for candidates without distro records or structured ranges",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    for (const c of ctx.candidates.filter(needsTextPath)) {
      assertLive(ctx);
      const text = [c.title, c.summary, c.details, c.kevInfo?.shortDescription].filter(Boolean).join("\n\n");
      try {
        c.textOnly = await extractAdvisory(ctx.sessionId, c, text);
      } catch (e) {
        ctx.notes.push(`advisory extraction failed for ${c.cve}: ${(e as Error).message}`);
      }
    }
    return inputData;
  },
});

const advisoryAnalysis = createStep({
  id: "advisory-analysis",
  description: "Sentinel advisory analyst (fetch tool only, untrusted text) → ThreatProfile per candidate, cached per CVE",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    await mapPool(ctx.candidates, 2, async (c) => {
      assertLive(ctx);
      const pkgs = ctx.hosts.flatMap((h) => c.sourcePkgs.map((s) => sourcesOf(h.inv).get(s)?.binaries.map((b) => b.name) ?? []).flat());
      const hostsContext = `${c.sourcePkgs.join(", ")} (installed binaries: ${[...new Set(pkgs)].sort().join(", ") || "n/a"})`;
      c.profile = await profileFor(`${ctx.sessionId}-profile-${c.cve}`, c, hostsContext, ctx.notes);
    });
    return inputData;
  },
});

const crossHostEvidence = createStep({
  id: "cross-host-evidence",
  description: "For each candidate, deterministic facts for EVERY host with the source package: distro verdict, listeners, firewall",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    for (const c of ctx.candidates) ctx.evidence.set(c.cve, buildEvidence(ctx, c));
    return inputData;
  },
});

const investigate = createStep({
  id: "investigate",
  description: "Sentinel investigator per (host, CVE) (read-only tools, cited steps) → code guardrails → remediation plan; unchanged pairs reuse the cached verdict",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    const work: { c: (typeof ctx.candidates)[number]; e: NonNullable<ReturnType<typeof ctx.evidence.get>>[number] }[] = [];
    for (const c of ctx.candidates) {
      for (const e of ctx.evidence.get(c.cve) ?? []) {
        const prev = getFindingByKey(e.hostId, c.cve);
        if (prev && prev.finding.investigation && prev.evidenceHash === evidenceHash(e, c.profile?.generatedAt ?? null)) continue; // cache hit
        work.push({ c, e });
      }
    }
    await mapPool(work, env.investigationConcurrency, async ({ c, e }) => {
      assertLive(ctx); // stop spending LLM calls (and querying hosts being recreated) once a reset cancelled the scan
      const t0 = Date.now();
      const k = await investigateHost(`${ctx.sessionId}-${e.hostId}-${c.cve}`, c, e, c.profile!);
      assertLive(ctx);
      if (k.status !== "not_affected") {
        const { plan, error } = await planRemediation(`${ctx.sessionId}-${e.hostId}-${c.cve}-plan`, c, k, c.profile!);
        assertLive(ctx);
        if (error) ctx.notes.push(`remediation planner failed for ${e.hostName}/${c.cve}, deterministic plan used: ${error}`);
        k.investigation.remediationPlan = plan;
        k.mitigations = mitigationsFromPlan(plan);
      }
      if (k.investigation.guardrail) ctx.notes.push(`guardrail ${e.hostName}/${c.cve}: ${k.investigation.guardrail}`);
      ctx.notes.push(`investigated ${e.hostName}/${c.cve} in ${((Date.now() - t0) / 1000).toFixed(1)}s → ${k.status} (${k.investigation.steps.length} steps)`);
      ctx.classified.push(k);
    });
    return inputData;
  },
});

const upsertFindings = createStep({
  id: "upsert-findings",
  description: "Upsert findings and audit new/changed ones",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    const now = nowIso();
    const byCve = new Map(ctx.candidates.map((c) => [c.cve, c]));
    const discovered = new Set<string>();
    const hadFindingsBefore = new Map(ctx.candidates.map((c) => [c.cve, listFindings({ cveId: c.cve }).length > 0]));
    const heldNow = heldSet(); // a demo reset may have happened while this scan was running
    for (const k of ctx.classified) {
      const c = byCve.get(k.cve)!;
      if (heldNow.has(c.cve)) continue;
      const e = k.evidence;
      const prev = getFindingByKey(e.hostId, c.cve)?.finding;
      const f: Finding = buildFinding(c, k, prev, now);
      saveFinding(f, k.evidenceHash);
      const SEV = { not_affected: 0, vulnerable_not_exposed: 1, exposed: 2 } as const;
      if (!discovered.has(c.cve) && !hadFindingsBefore.get(c.cve)) {
        discovered.add(c.cve);
        audit("cve_discovered", `New vulnerability: ${c.cve} — ${c.title}${c.cvss ? ` (CVSS ${c.cvss.split(" ")[0]})` : ""}${c.kev ? ", listed in CISA KEV" : ""}. Affects ${c.sourcePkgs.join(", ")} in the inventory.`, {
          cveId: c.cve, data: { kev: c.kev, reason: c.reason, aliases: c.aliases.slice(0, 6) },
        });
      }
      if (f.status !== "not_affected" && prev?.status !== f.status) {
        audit("vulnerable_detected", `${e.hostName} assessed ${statusLabel(f.status)} for ${c.cve}: ${e.sourcePackage} ${e.installedVersion}, ${f.status === "exposed" ? "reachable from the network" : "no network path to the vulnerable component"}.`, {
          hostId: f.hostId, cveId: c.cve, data: { findingId: f.id, status: f.status, priority: f.priority, from: prev?.status ?? null },
        });
      }
      if (f.status !== "not_affected" && (!prev || SEV[f.status] > SEV[prev.status])) ctx.escalated.push(f);
      if (!prev) {
        ctx.newFindings.push(f);
        audit("finding_new", `${e.hostName} · ${c.cve}: ${statusLabel(f.status)} (${priorityLabel(f.priority)})`, { hostId: f.hostId, cveId: f.cveId, data: { findingId: f.id } });
      } else if (prev.status !== f.status || prev.priority !== f.priority) {
        ctx.changedFindings.push(f);
        audit("finding_changed", `${e.hostName} · ${c.cve}: ${statusLabel(prev.status)} → ${statusLabel(f.status)} (${priorityLabel(f.priority)})`, { hostId: f.hostId, cveId: f.cveId, data: { findingId: f.id, from: prev.status } });
      }
    }
    // hosts that had a finding for a candidate CVE but no longer have the package at all → not_affected
    for (const c of ctx.candidates) {
      const covered = new Set((ctx.evidence.get(c.cve) ?? []).map((e) => e.hostId));
      for (const f of listFindings({ cveId: c.cve })) {
        if (covered.has(f.hostId) || f.status === "not_affected") continue;
        const host = ctx.hosts.find((h) => h.id === f.hostId);
        if (!host || (f.package && sourcesOf(host.inv).has(f.package.name))) continue;
        const prevStatus = f.status;
        Object.assign(f, {
          status: "not_affected", priority: "info", confidence: "high", updatedAt: now,
          rationale: `${f.package?.name ?? "The affected package"} is no longer installed on ${host.name}.`,
          mitigations: ["No action needed."],
        });
        saveFinding(f, "removed");
        ctx.changedFindings.push(f);
        audit("finding_changed", `${host.name} · ${c.cve}: ${statusLabel(prevStatus)} → Not Affected (package removed)`, { hostId: f.hostId, cveId: f.cveId });
      }
    }
    // Verdicts are final now: clear "re-assessing" progress labels without waiting for the report/plan steps.
    markRechecked(ctx.startedAt);
    return inputData;
  },
});

const reportStep = createStep({
  id: "report",
  description: "Queue ONE AI-written markdown report for new/changed exposed or vulnerable findings (written, saved + emailed in the background)",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    // only new findings or escalations (into exposed / vulnerable_not_exposed) trigger an email; de-escalations are audited only
    const actionable = ctx.escalated;
    if (!actionable.length) return inputData;
    const cves = [...new Set(actionable.map((f) => f.cveId))];
    const groups = cves.map((cve) => {
      const all = listFindings({ cveId: cve });
      return {
        candidate: ctx.candidates.find((c) => c.cve === cve)!,
        profile: ctx.candidates.find((c) => c.cve === cve)?.profile ?? null,
        findings: all.filter((f) => f.status !== "not_affected"),
        alsoChecked: all.filter((f) => f.status === "not_affected"),
      };
    }).filter((g) => g.candidate);
    const atRisk = new Set(groups.flatMap((g) => g.findings.map((f) => f.hostId)));
    const exposedN = new Set(groups.flatMap((g) => g.findings.filter((f) => f.status === "exposed").map((f) => f.hostId))).size;
    const kev = groups.some((g) => g.candidate.kev);
    const title = `[Prohori Sentinel] ${kev && exposedN ? "URGENT: " : ""}${cves.join(", ")} — ${exposedN} host(s) exposed, ${atRisk.size} host(s) need upgrade`;

    // Off the critical path: the scan finishes once findings + proposals are saved; the AI report (~1 min) is
    // written and emailed in the background. A reset meanwhile cancels the scan context, so nothing is saved.
    ctx.reportQueued = true;
    backgroundReports.add(ctx);
    void (async () => {
      let markdown: string;
      try {
        markdown = await writeReport(ctx.sessionId, { cves: groups, orgHosts: ctx.hosts.length });
      } catch (e) {
        console.warn(`[scan ${ctx.scanId}] AI report failed, using fallback: ${(e as Error).message}`);
        markdown = [`# ${title}`, ...groups.flatMap((g) => [
          `## ${g.candidate.cve} — ${g.candidate.title}`, `CISA KEV: ${g.candidate.kev ? "yes" : "no"}; CVSS ${g.candidate.cvss ?? "n/a"}`,
          ...g.findings.map((f) => `### ${f.evidence.hostName} — ${f.status} (${f.priority})\n\n${f.rationale}\n\nMitigations:\n${f.mitigations.map((m, i) => `${i + 1}. ${m}`).join("\n")}`),
          ...(g.alsoChecked.length ? ["### Also checked (not affected)", ...g.alsoChecked.map((f) => `- ${f.evidence.hostName}: ${f.rationale.split("\n")[0]}`)] : []),
        ])].join("\n\n");
      }
      if (ctx.cancelled) return; // a reset wiped the findings meanwhile
      const linked = groups.flatMap((g) => [...g.findings, ...g.alsoChecked]).filter((f) => getFinding(f.id));
      const report = {
        id: newId("rep"),
        createdAt: nowIso(),
        title,
        findingIds: linked.map((f) => f.id),
        markdown,
        emailedTo: [] as string[],
        emailedAt: null as string | null,
      };
      saveReport(report);
      for (const f of linked) {
        const cur = getFinding(f.id);
        if (cur) { cur.reportId = report.id; saveFinding(cur); }
      }
      ctx.reportId = report.id;
      audit("report_generated", `Report generated: "${title}" (${report.findingIds.length} findings)`, { data: { reportId: report.id, findingIds: report.findingIds, cves, scanId: ctx.scanId } });
      const to = getSettings().reportEmails;
      try {
        await sendReportEmail(to, title, markdown);
        if (ctx.cancelled) return; // email already went out; don't resurrect the report after a reset
        report.emailedTo = to;
        report.emailedAt = nowIso();
        saveReport(report);
        ctx.reportsSent++;
        audit("report_sent", `Report "${title}" emailed to ${to.join(", ")}`, { data: { reportId: report.id, recipients: to, findingIds: report.findingIds } });
      } catch (e) {
        if (ctx.cancelled) return;
        audit("error", `Report ${report.id} saved but email failed: ${(e as Error).message}`, { data: { reportId: report.id } });
      }
    })().catch((e) => console.error(`[scan ${ctx.scanId}] background report failed`, e))
      .finally(() => backgroundReports.delete(ctx));
    return inputData;
  },
});

/** The scan's auto-proposal rules for ONE exposed finding (all pending; a human approves): the plan's validated
 *  containment, and the upgrade only when a fixed build exists. Skips anything equivalent that already exists.
 *  Returns the number of new proposals. Also used by "Track as findings". */
export function proposeFixesFor(f: Finding, notes: string[]): number {
  let n = 0;
  const propose = (type: ActionType, params: Record<string, unknown>, reason: string) => {
    // don't re-propose what an admin rejected or revised away (rolled_back may be re-proposed)
    if (hasEquivalentAction(f.hostId, type, params, ["pending", "approved", "running", "applied", "rejected", "superseded"])) return;
    try {
      proposeAction({ hostId: f.hostId, findingId: f.id, type, params, proposedBy: "agent", reason });
      n++;
    } catch (e) {
      notes.push(`propose ${type} failed: ${(e as Error).message}`);
    }
  };
  if (f.status !== "exposed") return 0;
  const plan = f.investigation?.remediationPlan ?? [];
  // (a) the plan's immediate containment, if Sentinel found an allowed action for it (already validated in code)
  const containment = plan.find((p) => p.kind === "containment" && p.actionType && p.params);
  if (containment) {
    propose(containment.actionType as ActionType, containment.params!,
      `Immediate containment for ${f.cveId} on ${f.evidence.hostName}: ${containment.summary.replace(/\.$/, "")}. Trade-off: ${containment.tradeoff} Not a fix — the upgrade is still required.`);
  }
  // (b) the complete fix (package list filled by code from the inventory)
  const fix = plan.find((p) => p.kind === "fix" && p.actionType === "upgrade_packages" && p.params);
  if (fix && f.package?.fixedVersion) {
    propose("upgrade_packages", fix.params!,
      `${f.evidence.hostName} is exposed to ${f.cveId}${f.inKev ? " (CISA KEV)" : ""}: ${f.package.name} ${f.package.installedVersion} is vulnerable and reachable. Upgrading to ${f.package.fixedVersion} is the complete fix.`);
  }
  return n;
}

const proposeFixes = createStep({
  id: "propose-fixes",
  description: "Auto-propose (pending) the plan's containment and fix for exposed findings",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    // Pending proposals whose finding got resolved (e.g. after an upgrade) are closed automatically.
    closeObsoleteProposals((id) => getFinding(id)?.status ?? null);
    for (const f of listFindings({ status: "exposed" })) {
      if (!ctx.hosts.some((h) => h.id === f.hostId)) continue;
      ctx.proposedActions += proposeFixesFor(f, ctx.notes);
    }
    return inputData;
  },
});

export const scanWorkflow = createWorkflow({
  id: "prohori-scan",
  description: "Inventory → OSV → Sentinel triage → advisory parse → threat profiles → host facts → investigations + guardrails + plans → findings → propose fixes → report",
  inputSchema: IO,
  outputSchema: IO,
})
  .then(loadInventory)
  .then(osvMatchStep)
  .then(triageStep)
  .then(extractAdvisories)
  .then(advisoryAnalysis)
  .then(crossHostEvidence)
  .then(investigate)
  .then(upsertFindings)
  .then(proposeFixes) // before the report: approvals must not wait ~1 min for the AI report writer + email
  .then(reportStep)
  .commit();
