// Tools for the Prohori chat agent. There is deliberately NO approve tool: the AI can only propose.
import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { ACTION_DESCRIPTIONS, ACTION_TYPES, CONFIG_DIRECTIVE_ALLOWLIST, CONFIG_PATHS, QUERY_NAMES, type ActionType, type Finding } from "@prohori/shared";
import {
  audit, getFinding as dbGetFinding, getHostRow, getInventory as dbGetInventory, getSettings, hostSummary, listFindings as dbListFindings,
  listHostRows, newId, nowIso, saveFinding, saveReport, getAction as dbGetAction, listActions as dbListActions, getProfile as dbGetProfile,
  getJudgment as dbGetJudgment,
} from "../db";
import { hostQuery } from "../scan/facts";
import { actionCatalog } from "../scan/plan";
import { isOnline } from "../gateway";
import { computeHealth } from "../health";
import { proposeAction, reviseAction } from "../actions";
import { kevEntry } from "../vuln/kev";
import { allIds, cveOf, distroFixed, ecosystemFor, getVuln, getVulns, queryBatch, severityOf, upstreamRanges } from "../vuln/osv";
import { heldSet, isHeldVuln, sourcesOf, type Candidate } from "../scan/engine";
import { startScan, scanState } from "../scan/runner";
import { writeReport } from "../scan/ai";
import { sendReportEmail } from "../mailer";
import { slimJudgment, startJudgment } from "../scan/judge";

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
  execute: async () => ({ hosts: listHostRows().map((r) => ({ ...hostSummary(r, isOnline(r.id)), health: computeHealth(r.id) })) }),
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
  description: "Run one named, read-only query LIVE on a host via its daemon (falls back to the stored inventory if the daemon cannot answer). Only these names are allowed: " +
    QUERY_NAMES.join(", ") + `. "config_file" needs params {"path": "<file>"} matching one of: ${CONFIG_PATHS.join(", ")}.`,
  inputSchema: z.object({ hostId: hostIdSchema, queryName: z.enum(QUERY_NAMES), params: z.record(z.string(), z.string()).optional() }),
  execute: async ({ hostId, queryName, params }) => {
    const h = resolveHost(hostId);
    const r = await hostQuery(h.id, queryName, params ?? {});
    return { hostId: h.id, queryName, source: r.source, ...(r.note ? { note: r.note } : {}), ...(r.error ? { error: r.error } : {}), rowCount: r.rows.length, rows: r.rows.slice(0, 150) };
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
  description: "Query OSV live for one SOURCE package (as listed in the inventory's `source` field) at the version installed on a host, in the host's distro ecosystem. Shows which are KEV/critical.",
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
  description: "Full finding: rationale, mitigations, deterministic evidence (installed vs fixed build, listeners, firewall) and Sentinel's investigation (triage reason, preconditions with cited steps S1…, tool steps, conclusion, guardrail overrides, ranked remediation plan).",
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
      groups.push({ candidate: cand, profile: dbGetProfile(cve), findings: sel.filter((f) => f.status !== "not_affected"), alsoChecked: sel.filter((f) => f.status === "not_affected") });
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
  "Allowed actions (catalog from the daemon contract, JSON): " + JSON.stringify(actionCatalog().actions.map((a) => ({ type: a.type, description: a.description, constraint: a.constraint, params: a.params }))) +
  " Config directives allowed for set_config_directive: " + JSON.stringify(CONFIG_DIRECTIVE_ALLOWLIST) + ".";
void ACTION_DESCRIPTIONS;

export const getThreatProfileTool = createTool({
  id: "getThreatProfile",
  description: "Sentinel's cached threat profile of a CVE (derived from its advisories): component, attack vector, checkable preconditions, complete fix, partial mitigations with trade-offs, sources.",
  inputSchema: z.object({ cveId: z.string() }),
  execute: async ({ cveId }) => dbGetProfile(cveId.toUpperCase()) ?? { cveId, error: "no threat profile yet (Sentinel builds one when a scan selects the CVE for investigation)" },
});

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

export const judgeAdvisoryTool = createTool({
  id: "judgeAdvisory",
  description:
    "Judge ONE advisory URL (https) against every host, without the scan feed: Sentinel reads the page, checks distro records for the build's fix status, investigates each host with the affected package and plans remediation. " +
    "Runs in the background (a few minutes) and returns at once with a judgment id (jdg_…); the chat shows a live card. The result is NOT a finding until the admin clicks \"Track as findings\". " +
    "Pass focus when the page covers several bugs and the admin named one; pass cveId only if the admin gave one.",
  inputSchema: z.object({
    url: z.string().describe("the advisory URL the admin gave (https)"),
    cveId: z.string().optional().describe("CVE id, only if the admin stated it"),
    focus: z.string().optional().describe("which bug on the page to judge, if the admin named one (e.g. 'the SRP authentication bypass')"),
  }),
  execute: async ({ url, cveId, focus }, ctx) => {
    try {
      const { threadId, actor } = chatCtx(ctx);
      return slimJudgment(await startJudgment({ url, cveId: cveId ?? null, focus: focus ?? null, threadId, actor: actor ?? "unknown" }));
    } catch (e) {
      return { error: (e as Error).message };
    }
  },
});

export const getJudgmentTool = createTool({
  id: "getJudgment",
  description: "Current state and result of an advisory judgment (jdg_…): progress, the advisory facts (CVE id, ranges, fix availability, distro records consulted), and per host: status, fix-status source (distro_record vs advisory_only), version-only verdict, reachability, rationale, how the package was matched.",
  inputSchema: z.object({ judgmentId: z.string() }),
  execute: async ({ judgmentId }) => {
    const j = dbGetJudgment(judgmentId.trim());
    return j ? slimJudgment(j) : { error: "judgment not found" };
  },
});

export const prohoriTools = {
  judgeAdvisory: judgeAdvisoryTool,
  getJudgment: getJudgmentTool,
  listHosts: listHostsTool,
  getInventory: getInventoryTool,
  runHostQuery: runHostQueryTool,
  lookupCve: lookupCveTool,
  checkKev: checkKevTool,
  findVulnsForPackage: findVulnsForPackageTool,
  listFindings: listFindingsTool,
  getFinding: getFindingTool,
  getThreatProfile: getThreatProfileTool,
  runScanNow: runScanNowTool,
  sendReport: sendReportTool,
  proposeFix: proposeFixTool,
  reviseProposal: reviseProposalTool,
  getAction: getActionTool,
  listActions: listActionsTool,
};

void getHostRow;
