// The scan as a Mastra workflow with fixed, deterministic step order. AI runs only inside
// extract-advisories, classify and report. Heavy data stays in an in-memory ScanContext keyed by scanId;
// steps pass only { scanId } so workflow snapshots stay small.
import { createStep, createWorkflow } from "@mastra/core/workflows";
import { z } from "zod";
import type { Finding } from "@prohori/shared";
import { audit, getFindingByKey, getSettings, listFindings, newId, nowIso, saveFinding, saveReport, getFinding } from "../db";
import { sendReportEmail } from "../mailer";
import { closeObsoleteProposals, hasEquivalentAction, proposeAction } from "../actions";
import { classifyCve, extractAdvisory, writeReport, type Classification } from "./ai";
import {
  buildEvidence, evidenceHash, heldSet, expectedStatus, fallbackRationale, loadHosts, needsTextPath, osvMatch, priorityFor,
  signalFilter, sourcesOf, type Candidate, type Classified, type ScanContext,
} from "./engine";

export const scanContexts = new Map<string, ScanContext>();
const IO = z.object({ scanId: z.string() });
const ctxOf = (scanId: string) => {
  const c = scanContexts.get(scanId);
  if (!c) throw new Error(`scan context ${scanId} missing`);
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

const signalFilterStep = createStep({
  id: "signal-filter",
  description: "Keep only KEV / critical CVEs as candidates",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    await signalFilter(ctxOf(inputData.scanId));
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

const crossHostEvidence = createStep({
  id: "cross-host-evidence",
  description: "For each candidate, evaluate EVERY host with the source package: naive vs distro verdict, reachability, config",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    for (const c of ctx.candidates) ctx.evidence.set(c.cve, buildEvidence(ctx, c));
    return inputData;
  },
});

function enforce(c: Candidate, e: ReturnType<typeof buildEvidence>[number], llm: Classification | undefined): Classified {
  const { status, uncertain } = expectedStatus(e);
  const notes: string[] = [];
  let rationale = llm?.rationale?.trim() || fallbackRationale(e, status);
  if (llm && llm.status !== status) {
    notes.push(`_Sentinel override: the AI suggested **${llm.status}**, but the deterministic evidence gives **${status}** (distro verdict ${e.distroVerdict}, reachable ${e.reachable}); the evidence wins._`);
  }
  const needsConfirmation = e.needsConfirmation || uncertain;
  if (needsConfirmation) notes.push("_Needs confirmation: part of this verdict rests on uncertain or AI-parsed evidence; Sentinel chose the more severe status._");
  if (notes.length) rationale += "\n\n" + notes.join("\n\n");

  let mitigations = (llm?.mitigations ?? []).filter(Boolean);
  if (status !== "not_affected") {
    const pkgs = e.binaries.join(" ");
    const complete = e.distroFixed
      ? `Upgrade ${e.sourcePackage} packages (${pkgs}) to ${e.distroFixed} or later — complete fix${/^CVE-2026-10961[89]$/.test(c.cve) ? " (upgrade is the only complete fix)" : ""}`
      : `Upgrade ${e.sourcePackage} to a patched build when the distribution publishes one`;
    if (!mitigations.length || !/upgrad/i.test(mitigations[0]!)) mitigations = [complete, ...mitigations.filter((m) => !/upgrad/i.test(m))];
    else if (!/complete fix/i.test(mitigations[0]!)) {
      mitigations[0] = `${mitigations[0]!.replace(/\.$/, "")} — complete fix${/^CVE-2026-10961[89]$/.test(c.cve) ? " (upgrade is the only complete fix)" : ""}`;
    }
    if (status === "exposed" && e.exposedPorts.length && !mitigations.some((m) => /firewall|close .*port/i.test(m))) {
      mitigations.splice(1, 0, `Close ${e.exposedPorts.map((p) => `${p}/tcp`).join(", ")} in the host firewall — immediate containment, not a fix (the site on that port goes offline until patched)`);
    }
    mitigations = mitigations.map((m, i) => {
      if (i === 0) return m;
      if (/firewall|close .*port/i.test(m)) return /containment/i.test(m) ? m : `${m} (containment, not a fix)`;
      return !/partial/i.test(m) && /php\.ini|memory_limit|post_max_size|max_input|multipart|nginx|disable|block/i.test(m) ? `${m} (partial)` : m;
    });
  } else if (!mitigations.length) {
    mitigations = ["No action needed; keep receiving distro security updates."];
  }
  const confidence = needsConfirmation ? (llm?.confidence === "high" ? "medium" : llm?.confidence ?? "low") : llm?.confidence ?? "high";
  return {
    cve: c.cve,
    evidence: e,
    status,
    priority: priorityFor(status, c.kev),
    confidence,
    rationale,
    mitigations,
    needsConfirmation,
    evidenceHash: evidenceHash(e),
  };
}

const classify = createStep({
  id: "classify",
  description: "AI classification (structured output) per CVE, then deterministic hard rules override the AI",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    for (const c of ctx.candidates) {
      const ev = ctx.evidence.get(c.cve) ?? [];
      if (!ev.length) continue;
      // skip the LLM if every host's evidence is unchanged since the last classification
      const unchanged = ev.every((e) => getFindingByKey(e.hostId, c.cve)?.evidenceHash === evidenceHash(e));
      if (unchanged) continue;
      let llm: Classification[] = [];
      try {
        llm = await classifyCve(ctx.sessionId, c, ev);
      } catch (e) {
        ctx.notes.push(`AI classification failed for ${c.cve}, using deterministic rationale: ${(e as Error).message}`);
      }
      for (const e of ev) ctx.classified.push(enforce(c, e, llm.find((l) => l.hostId === e.hostId)));
    }
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
      const f: Finding = {
        id: prev?.id ?? `f_${e.hostId}_${c.cve}`,
        hostId: e.hostId,
        cveId: c.cve,
        aliases: c.aliases,
        title: c.title,
        status: k.status,
        priority: k.priority,
        confidence: k.confidence,
        needsConfirmation: k.needsConfirmation,
        inKev: c.kev,
        cvss: c.cvss,
        package: { name: e.sourcePackage!, installedVersion: e.installedVersion!, fixedVersion: e.distroFixed },
        naiveVerdict: e.naiveVerdict,
        rationale: k.rationale,
        mitigations: k.mitigations,
        evidence: {
          hostName: e.hostName,
          installed: `${e.sourcePackage} ${e.installedVersion} (upstream ${e.upstreamVersion})`,
          binaries: e.binaries.join(", "),
          fixed: e.distroFixed ?? "unknown",
          versionCheck: e.installedVsFixed,
          distroVerdict: e.distroVerdict,
          naiveVerdict: e.naiveVerdict,
          reachability: e.reachability,
          listening: e.listening.join("; ") || "nothing on non-loopback addresses",
          firewall: e.firewall,
          ...(e.exposedPorts.length ? { exposedPorts: e.exposedPorts.map((p) => `${p}/tcp`).join(", ") } : {}),
          webSapi: e.webSapi.join(", ") || "none",
          kev: c.kev ? `yes (added ${c.kevInfo?.dateAdded})` : "no",
          cvss: c.cvss ?? "n/a",
          ...(Object.keys(e.config).length ? { config: Object.entries(e.config).map(([key, v]) => `${key}=${v}`).join("; ") } : {}),
        },
        firstSeen: prev?.firstSeen ?? now,
        updatedAt: now,
        reportId: prev?.reportId ?? null,
      };
      saveFinding(f, k.evidenceHash);
      const SEV = { not_affected: 0, vulnerable_not_exposed: 1, exposed: 2 } as const;
      if (!discovered.has(c.cve) && !hadFindingsBefore.get(c.cve)) {
        discovered.add(c.cve);
        audit("cve_discovered", `Sentinel discovered ${c.cve} (${c.title})${c.kev ? " — on CISA KEV" : ""}${c.cvss ? `, CVSS ${c.cvss.split(" ")[0]}` : ""}; affects ${c.sourcePkgs.join(", ")} in our inventory`, {
          cveId: c.cve, data: { kev: c.kev, reason: c.reason, aliases: c.aliases.slice(0, 6) },
        });
      }
      if (f.status !== "not_affected" && prev?.status !== f.status) {
        audit("vulnerable_detected", `${e.hostName} is ${f.status === "exposed" ? "EXPOSED" : "vulnerable (not exposed)"} to ${c.cve}: ${e.sourcePackage} ${e.installedVersion}; ${e.reachability}`, {
          hostId: f.hostId, cveId: c.cve, data: { findingId: f.id, status: f.status, priority: f.priority, from: prev?.status ?? null },
        });
      }
      if (f.status !== "not_affected" && (!prev || SEV[f.status] > SEV[prev.status])) ctx.escalated.push(f);
      if (!prev) {
        ctx.newFindings.push(f);
        audit("finding_new", `${e.hostName}: ${c.cve} → ${f.status} (${f.priority})`, { hostId: f.hostId, cveId: f.cveId, data: { findingId: f.id } });
      } else if (prev.status !== f.status || prev.priority !== f.priority) {
        ctx.changedFindings.push(f);
        audit("finding_changed", `${e.hostName}: ${c.cve} ${prev.status} → ${f.status} (${f.priority})`, { hostId: f.hostId, cveId: f.cveId, data: { findingId: f.id, from: prev.status } });
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
        audit("finding_changed", `${host.name}: ${c.cve} ${prevStatus} → not_affected (package removed)`, { hostId: f.hostId, cveId: f.cveId });
      }
    }
    return inputData;
  },
});

const reportStep = createStep({
  id: "report",
  description: "AI writes ONE markdown report for new/changed exposed or vulnerable findings; save + email",
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
        findings: all.filter((f) => f.status !== "not_affected"),
        alsoChecked: all.filter((f) => f.status === "not_affected"),
      };
    }).filter((g) => g.candidate);
    const atRisk = new Set(groups.flatMap((g) => g.findings.map((f) => f.hostId)));
    const exposedN = new Set(groups.flatMap((g) => g.findings.filter((f) => f.status === "exposed").map((f) => f.hostId))).size;
    const kev = groups.some((g) => g.candidate.kev);
    const title = `[Prohori Sentinel] ${kev && exposedN ? "URGENT: " : ""}${cves.join(", ")} — ${exposedN} host(s) exposed, ${atRisk.size} host(s) need upgrade`;

    let markdown: string;
    try {
      markdown = await writeReport(ctx.sessionId, { cves: groups, orgHosts: ctx.hosts.length });
    } catch (e) {
      ctx.notes.push(`AI report failed, using fallback: ${(e as Error).message}`);
      markdown = [`# ${title}`, ...groups.flatMap((g) => [
        `## ${g.candidate.cve} — ${g.candidate.title}`, `CISA KEV: ${g.candidate.kev ? "yes" : "no"}; CVSS ${g.candidate.cvss ?? "n/a"}`,
        ...g.findings.map((f) => `### ${f.evidence.hostName} — ${f.status} (${f.priority})\n\n${f.rationale}\n\nMitigations:\n${f.mitigations.map((m, i) => `${i + 1}. ${m}`).join("\n")}`),
        ...(g.alsoChecked.length ? ["### Also checked (not affected)", ...g.alsoChecked.map((f) => `- ${f.evidence.hostName}: ${f.rationale.split("\n")[0]}`)] : []),
      ])].join("\n\n");
    }
    const linked = groups.flatMap((g) => [...g.findings, ...g.alsoChecked]);
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
    audit("report_generated", `Report generated: "${title}" (${report.findingIds.length} findings)`, { data: { reportId: report.id, findingIds: report.findingIds, cves } });
    const to = getSettings().reportEmails;
    try {
      await sendReportEmail(to, title, markdown);
      report.emailedTo = to;
      report.emailedAt = nowIso();
      saveReport(report);
      ctx.reportsSent++;
      audit("report_sent", `Report "${title}" emailed to ${to.join(", ")}`, { data: { reportId: report.id, recipients: to, findingIds: report.findingIds } });
    } catch (e) {
      audit("error", `Report ${report.id} saved but email failed: ${(e as Error).message}`, { data: { reportId: report.id } });
    }
    return inputData;
  },
});

const proposeFixes = createStep({
  id: "propose-fixes",
  description: "Auto-propose (pending) upgrade actions for exposed findings with a distro fix",
  inputSchema: IO, outputSchema: IO,
  execute: async ({ inputData }) => {
    const ctx = ctxOf(inputData.scanId);
    // Pending proposals whose finding got resolved (e.g. after an upgrade) are closed automatically.
    closeObsoleteProposals((id) => getFinding(id)?.status ?? null);
    if (!getSettings().tier2Enabled) return inputData;
    const propose = (f: Finding, type: "firewall_port" | "upgrade_packages", params: Record<string, unknown>, reason: string) => {
      // don't re-propose what an admin rejected or revised away (rolled_back may be re-proposed)
      if (hasEquivalentAction(f.hostId, type, params, ["pending", "approved", "running", "applied", "rejected", "superseded"])) return;
      try {
        proposeAction({ hostId: f.hostId, findingId: f.id, type, params, proposedBy: "agent", reason });
        ctx.proposedActions++;
      } catch (e) {
        ctx.notes.push(`propose ${type} failed: ${(e as Error).message}`);
      }
    };
    for (const f of listFindings({ status: "exposed" })) {
      const host = ctx.hosts.find((h) => h.id === f.hostId);
      if (!host) continue;
      // (a) immediate containment: close the public port(s) the vulnerable service is reachable on
      const ev = ctx.evidence.get(f.cveId)?.find((e) => e.hostId === f.hostId);
      const ports = ev?.exposedPorts ?? (f.evidence.exposedPorts ?? "").split(",").map((s) => parseInt(s, 10)).filter((n) => n > 0);
      for (const port of ports.filter((p) => p !== 22)) {
        propose(f, "firewall_port", { port, protocol: "tcp", state: "closed" },
          `Immediate containment for ${f.cveId} on ${f.evidence.hostName}: closing ${port}/tcp removes network exposure; the site on this port goes offline until patched. Not a fix — upgrade is still required.`);
      }
      // (b) the complete fix: upgrade every installed binary of the vulnerable source package
      if (f.package?.fixedVersion) {
        const pkgs = (sourcesOf(host.inv).get(f.package.name)?.binaries ?? []).map((b) => b.name).sort().slice(0, 20);
        if (pkgs.length) {
          propose(f, "upgrade_packages", { packages: pkgs },
            `${f.evidence.hostName} is exposed to ${f.cveId}${f.inKev ? " (CISA KEV)" : ""}: ${f.package.name} ${f.package.installedVersion} is vulnerable and reachable. Upgrading to ${f.package.fixedVersion} is the complete fix.`);
        }
      }
    }
    return inputData;
  },
});

export const scanWorkflow = createWorkflow({
  id: "prohori-scan",
  description: "Inventory → OSV → signal filter → advisory parse → cross-host evidence → classify → findings → report → propose fixes",
  inputSchema: IO,
  outputSchema: IO,
})
  .then(loadInventory)
  .then(osvMatchStep)
  .then(signalFilterStep)
  .then(extractAdvisories)
  .then(crossHostEvidence)
  .then(classify)
  .then(upsertFindings)
  .then(reportStep)
  .then(proposeFixes)
  .commit();
