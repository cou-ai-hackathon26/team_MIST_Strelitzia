// Tools for the Prohori chat agent. There is deliberately NO approve tool: the AI can only propose.
import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { ACTION_TYPES, QUERY_NAMES, type ActionType, type Finding } from "@prohori/shared";
import {
  audit, getFinding as dbGetFinding, getHostRow, getInventory as dbGetInventory, getSettings, hostSummary, listFindings as dbListFindings,
  listHostRows, newId, nowIso, saveFinding, saveReport, getAction as dbGetAction, listActions as dbListActions,
} from "../db";
import { isOnline, queryHost } from "../gateway";
import { proposeAction, reviseAction } from "../actions";
import { kevEntry } from "../vuln/kev";
import { allIds, cveOf, distroFixed, ecosystemFor, getVuln, getVulns, queryBatch, severityOf, upstreamRanges } from "../vuln/osv";
import { heldSet, isHeldVuln, sourcesOf, type Candidate } from "../scan/engine";
import { startScan, scanState } from "../scan/runner";
import { writeReport } from "../scan/ai";
import { sendReportEmail } from "../mailer";

const hostIdSchema = z.string().describe("Host id, e.g. web-a (use listHosts to map names like bank-web-02 to ids)");

function resolveHost(idOrName: string) {
  const rows = listHostRows();
  const r = rows.find((h) => h.id === idOrName) ?? rows.find((h) => h.name.toLowerCase() === idOrName.toLowerCase());
  if (!r) throw new Error(`unknown host "${idOrName}". Known: ${rows.map((h) => `${h.id} (${h.name})`).join(", ")}`);
  return r;
}

function slimFinding(f: Finding) {
  return {
    id: f.id, hostId: f.hostId, host: f.evidence.hostName, cveId: f.cveId, title: f.title, status: f.status, priority: f.priority,
    confidence: f.confidence, needsConfirmation: f.needsConfirmation, inKev: f.inKev, package: f.package, naiveVerdict: f.naiveVerdict,
  };
}

export const listHostsTool = createTool({
  id: "listHosts",
  description: "List all monitored hosts with online status, OS, finding counts .",
  inputSchema: z.object({}),
  execute: async () => ({ hosts: listHostRows().map((r) => hostSummary(r, isOnline(r.id))) }),
});

export const getInventoryTool = createTool({
  id: "getInventory",
  description: "Latest stored inventory of a host (OS, installed packages with source package, listening ports, processes, config).",
  inputSchema: z.object({ hostId: hostIdSchema, packageFilter: z.string().optional().describe("Only packages whose name/source contains this text") }),
  execute: async ({ hostId, packageFilter }) => {
    const h = resolveHost(hostId);
    const inv = dbGetInventory(h.id);
    if (!inv) return { hostId: h.id, error: "no inventory received yet" };
    const pk = packageFilter ? inv.packages.filter((p) => p.name.includes(packageFilter) || p.source.includes(packageFilter)) : inv.packages;
    return {
      hostId: h.id, name: h.name, collectedAt: inv.collectedAt, os: inv.os,
      packageCount: inv.packages.length, packages: pk.slice(0, 150).map((p) => ({ name: p.name, version: p.version, source: p.source })),
      listeningPorts: inv.listeningPorts, processes: inv.processes.slice(0, 80).map((p) => p.name), config: inv.config,
    };
  },
});

export const runHostQueryTool = createTool({
  id: "runHostQuery",
  description: "Run one named, read-only osquery query LIVE on a host via its daemon. Only these names are allowed: " + QUERY_NAMES.join(", "),
  inputSchema: z.object({ hostId: hostIdSchema, queryName: z.enum(QUERY_NAMES) }),
  execute: async ({ hostId, queryName }) => {
    const h = resolveHost(hostId);
    try {
      const rows = await queryHost(h.id, queryName);
      return { hostId: h.id, queryName, rowCount: rows.length, rows: rows.slice(0, 150) };
    } catch (e) {
      return { hostId: h.id, queryName, error: (e as Error).message };
    }
  },
});

export const lookupCveTool = createTool({
  id: "lookupCve",
  description: "Look up a CVE (or UBUNTU-/DEBIAN-/GHSA- id): summary, details, severity, upstream affected ranges, distro fixed versions for our hosts' OS, CISA KEV status.",
  inputSchema: z.object({ id: z.string() }),
  execute: async ({ id }) => {
    const rec = await getVuln(id.toUpperCase());
    const cve = (rec && cveOf(rec)) ?? id.toUpperCase();
    const [cveRec, ubuntu, debian] = await Promise.all([getVuln(cve), getVuln(`UBUNTU-${cve}`), getVuln(`DEBIAN-${cve}`)]);
    if (!cveRec && !ubuntu && !debian && !rec) return { id, error: "not found in OSV" };
    const ecos = new Set(listHostRows().map((h) => ecosystemFor(dbGetInventory(h.id)?.os)).filter(Boolean) as string[]);
    const distroFixes: { ecosystem: string; package: string; fixed: string | null }[] = [];
    for (const r of [ubuntu, debian]) for (const a of r?.affected ?? []) {
      if (a.package && ecos.has(a.package.ecosystem)) distroFixes.push({ ecosystem: a.package.ecosystem, package: a.package.name, fixed: distroFixed(r, a.package.ecosystem, a.package.name).fixed });
    }
    const k = kevEntry(cve);
    const held = heldSet().has(cve);
    return {
      cve, aliases: [...new Set([cveRec, ubuntu, debian].flatMap((r) => (r ? allIds(r) : [])))].filter((x) => x !== cve).slice(0, 12),
      summary: cveRec?.summary ?? ubuntu?.summary ?? "", details: (cveRec?.details ?? ubuntu?.details ?? "").slice(0, 1500),
      published: cveRec?.published ?? ubuntu?.published,
      severity: [cveRec, ubuntu].map((r) => severityOf(r)),
      upstreamAffectedRanges: upstreamRanges(cveRec), distroFixedVersions: distroFixes,
      kev: k ? { inKev: true, ...k } : { inKev: false },
      ...(held ? { note: "This CVE is currently held back by demo replay mode; scans ignore it until injected." } : {}),
    };
  },
});

export const checkKevTool = createTool({
  id: "checkKev",
  description: "Check whether a CVE is on the CISA Known Exploited Vulnerabilities catalog.",
  inputSchema: z.object({ cveId: z.string() }),
  execute: async ({ cveId }) => {
    const k = kevEntry(cveId);
    return k ? { cveId, inKev: true, ...k } : { cveId, inKev: false };
  },
});

export const findVulnsForPackageTool = createTool({
  id: "findVulnsForPackage",
  description: "Query OSV live for one SOURCE package (e.g. php8.3) at the version installed on a host, in the host's distro ecosystem. Shows which are KEV/critical.",
  inputSchema: z.object({ hostId: hostIdSchema, sourcePackage: z.string() }),
  execute: async ({ hostId, sourcePackage }) => {
    const h = resolveHost(hostId);
    const inv = dbGetInventory(h.id);
    if (!inv) return { error: "no inventory" };
    const eco = ecosystemFor(inv.os);
    const src = sourcesOf(inv).get(sourcePackage);
    if (!eco || !src) return { hostId: h.id, sourcePackage, error: !eco ? "unsupported OS" : "source package not installed on this host" };
    const [ids] = await queryBatch([{ name: sourcePackage, version: src.version, ecosystem: eco }]);
    const details = await getVulns(ids ?? []);
    const held = heldSet();
    const vulns = (ids ?? []).filter((id) => !isHeldVuln(details.get(id) ?? null, id, held)).map((id) => {
      const v = details.get(id) ?? null;
      const c = v ? cveOf(v) : null;
      const s = severityOf(v);
      return { id, cve: c, distroSeverity: s.label, cvss: s.score, inKev: c ? !!kevEntry(c) : false };
    });
    const important = vulns.filter((v) => v.inKev || v.distroSeverity === "critical" || (!v.distroSeverity && (v.cvss ?? 0) >= 9));
    return { hostId: h.id, sourcePackage, installedVersion: src.version, ecosystem: eco, rawMatchCount: vulns.length, kevOrCritical: important, others: vulns.filter((v) => !important.includes(v)).slice(0, 40) };
  },
});

export const listFindingsTool = createTool({
  id: "listFindings",
  description: "List current findings (one per host+CVE), optionally filtered by status, hostId or cveId. Sorted by priority.",
  inputSchema: z.object({
    status: z.enum(["exposed", "vulnerable_not_exposed", "not_affected"]).optional(),
    hostId: z.string().optional(),
    cveId: z.string().optional(),
  }),
  execute: async ({ status, hostId, cveId }) => {
    const hid = hostId ? resolveHost(hostId).id : undefined;
    return { findings: dbListFindings({ status, hostId: hid, cveId: cveId?.toUpperCase() }).map(slimFinding) };
  },
});

export const getFindingTool = createTool({
  id: "getFinding",
  description: "Full finding with rationale, mitigations and the deterministic evidence (installed vs fixed build, reachability, listening ports, config).",
  inputSchema: z.object({ id: z.string() }),
  execute: async ({ id }) => dbGetFinding(id) ?? { error: "finding not found" },
});

export const runScanNowTool = createTool({
  id: "runScanNow",
  description: "Start a vulnerability scan of all hosts now (no-op if one is already running). Results arrive asynchronously.",
  inputSchema: z.object({}),
  execute: async () => ({ started: startScan("chat"), scan: scanState() }),
});

export const sendReportTool = createTool({
  id: "sendReport",
  description: "Write a report covering the given finding ids and email it to the configured report recipients.",
  inputSchema: z.object({ findingIds: z.array(z.string()).min(1) }),
  execute: async ({ findingIds }, ctx) => {
    const fs = findingIds.map((id) => dbGetFinding(id)).filter(Boolean) as Finding[];
    if (!fs.length) return { error: "no such findings" };
    const groups = [];
    for (const cve of [...new Set(fs.map((f) => f.cveId))]) {
      const [cveRec, ubuntu] = await Promise.all([getVuln(cve), getVuln(`UBUNTU-${cve}`)]);
      const f0 = fs.find((f) => f.cveId === cve)!;
      const k = kevEntry(cve);
      const cand = {
        cve, aliases: f0.aliases, title: f0.title, summary: cveRec?.summary ?? ubuntu?.summary ?? "", details: (cveRec?.details ?? "").slice(0, 2000),
        kev: !!k, kevInfo: k, cvss: f0.cvss,
      } as unknown as Candidate;
      const sel = fs.filter((f) => f.cveId === cve);
      groups.push({ candidate: cand, findings: sel.filter((f) => f.status !== "not_affected"), alsoChecked: sel.filter((f) => f.status === "not_affected") });
    }
    const session = `prohori-report-${(ctx as any)?.agent?.threadId ?? crypto.randomUUID()}`;
    const markdown = await writeReport(session, { cves: groups, orgHosts: listHostRows().length });
    const title = `[Prohori Sentinel] Report: ${groups.map((g) => g.candidate.cve).join(", ")} (${fs.length} finding(s))`;
    const report = { id: newId("rep"), createdAt: nowIso(), title, findingIds: fs.map((f) => f.id), markdown, emailedTo: [] as string[], emailedAt: null as string | null };
    saveReport(report);
    audit("report_generated", `Report generated from chat: "${title}"`, { data: { reportId: report.id, findingIds: report.findingIds } });
    for (const f of fs) { f.reportId = report.id; saveFinding(f); }
    const to = getSettings().reportEmails;
    try {
      await sendReportEmail(to, title, markdown);
      report.emailedTo = to;
      report.emailedAt = nowIso();
      saveReport(report);
      audit("report_sent", `Report "${title}" emailed to ${to.join(", ")} (requested in chat)`, { data: { reportId: report.id, recipients: to } });
      return { reportId: report.id, title, emailedTo: to };
    } catch (e) {
      audit("error", `Report ${report.id} saved but email failed: ${(e as Error).message}`);
      return { reportId: report.id, title, emailError: (e as Error).message };
    }
  },
});

function chatCtx(ctx: any): { threadId: string | null; actor: string | null } {
  const rc = ctx?.requestContext;
  return {
    threadId: (rc?.get?.("threadId") as string | undefined) ?? ctx?.agent?.threadId ?? null,
    actor: (rc?.get?.("actor") as string | undefined) ?? null,
  };
}

const actionTypeSchema = z.enum(ACTION_TYPES as [ActionType, ...ActionType[]]);
const ACTION_TYPES_HELP =
  "Types: firewall_port {port: number, protocol: 'tcp'|'udp', state: 'closed'|'open'} (immediate containment, takes the service on that port offline; NOT a fix; port 22 refused), " +
  "upgrade_packages {packages: string[]} (complete fix), nginx_block_multipart {} (partial: blocks uploads, site stays up), " +
  "set_php_directive {sapi: 'fpm'|'cli'|'apache2', directive, value} (partial), restart_service {service: 'nginx'|'php8.3-fpm'}.";

export const proposeFixTool = createTool({
  id: "proposeFix",
  description:
    "PROPOSE a remediation action for a host. It is created as PENDING; a human must click Approve in the dashboard. You cannot approve or apply it. " +
    ACTION_TYPES_HELP + " Returns the full ActionRecord.",
  inputSchema: z.object({
    hostId: hostIdSchema,
    findingId: z.string().optional(),
    actionType: actionTypeSchema,
    params: z.record(z.string(), z.unknown()),
    reason: z.string(),
  }),
  execute: async ({ hostId, findingId, actionType, params, reason }, ctx) => {
    try {
      const h = resolveHost(hostId);
      const { threadId } = chatCtx(ctx);
      return proposeAction({ hostId: h.id, findingId: findingId ?? null, type: actionType, params, reason, proposedBy: "agent", threadId });
    } catch (e) {
      return { error: (e as Error).message };
    }
  },
});

export const reviseProposalTool = createTool({
  id: "reviseProposal",
  description:
    "Revise a PENDING proposal when the admin wants a different mitigation: creates a NEW pending action (supersedes the old one, which becomes 'superseded'). " +
    "Still needs a human Approve click. " + ACTION_TYPES_HELP + " Returns the new full ActionRecord.",
  inputSchema: z.object({ actionId: z.string(), actionType: actionTypeSchema, params: z.record(z.string(), z.unknown()), reason: z.string() }),
  execute: async ({ actionId, actionType, params, reason }, ctx) => {
    try {
      const { threadId, actor } = chatCtx(ctx);
      return reviseAction(actionId, { type: actionType, params, reason, threadId, requestedBy: actor ?? undefined });
    } catch (e) {
      return { error: (e as Error).message };
    }
  },
});

export const getActionTool = createTool({
  id: "getAction",
  description: "Get one remediation action (full ActionRecord: type, params, reason, state, who decided, note, thread, revisions, result).",
  inputSchema: z.object({ actionId: z.string() }),
  execute: async ({ actionId }) => dbGetAction(actionId) ?? { error: "action not found" },
});

export const listActionsTool = createTool({
  id: "listActions",
  description: "List remediation actions, optionally filtered by state (pending, approved, running, applied, failed, rejected, rolled_back, superseded) and/or hostId.",
  inputSchema: z.object({ state: z.string().optional(), hostId: z.string().optional() }),
  execute: async ({ state, hostId }) => {
    const hid = hostId ? resolveHost(hostId).id : undefined;
    return { actions: dbListActions({ state, hostId: hid }).slice(0, 30) };
  },
});

export const prohoriTools = {
  listHosts: listHostsTool,
  getInventory: getInventoryTool,
  runHostQuery: runHostQueryTool,
  lookupCve: lookupCveTool,
  checkKev: checkKevTool,
  findVulnsForPackage: findVulnsForPackageTool,
  listFindings: listFindingsTool,
  getFinding: getFindingTool,
  runScanNow: runScanNowTool,
  sendReport: sendReportTool,
  proposeFix: proposeFixTool,
  reviseProposal: reviseProposalTool,
  getAction: getActionTool,
  listActions: listActionsTool,
};

void getHostRow;
