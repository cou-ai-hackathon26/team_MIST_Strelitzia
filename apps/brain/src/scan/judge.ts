// "Judge an advisory": the admin hands Sentinel an advisory URL; Sentinel judges that one vulnerability against every
// host WITHOUT the scan feed (no OSV package match, no triage, ignore list bypassed). The page is the source for
// what/how; distro records (OSV UBUNTU-/DEBIAN-<CVE>), when a CVE id is known, decide whether the build is patched.
// Investigation, guardrails and planning are the scan's own (investigateHost / planRemediation). Results stay in
// the judgments table until the admin clicks "Track as findings".
import type { AdvisoryJudgment, Finding, JudgmentHost, ThreatProfile } from "@prohori/shared";
import {
  audit, getFindingByKey, getJudgment, getJudgmentInternal, listFindings, newId, nowIso, saveFinding, saveJudgment,
  saveProfile, saveTriage,
} from "../db";
import { env } from "../env";
import { HttpError } from "../actions";
import { assertPublicUrl, safeFetch } from "../net/safefetch";
import { kevEntry } from "../vuln/kev";
import { allIds, ecosystemFor, getVuln, upstreamRanges, type OsvVuln } from "../vuln/osv";
import type { VersionRange } from "../vuln/versions";
import { upstreamVersion } from "../vuln/versions";
import { extractJudgment, type JudgmentExtraction } from "./ai";
import {
  bestSeverity, buildFinding, closedPortsOf, evidenceHash, externalListeners, factsDigestOf, firewallText, fmtListener,
  loadHosts, priorityFor, sourcesOf, statusLabel, priorityLabel, type Candidate, type Classified, type Evidence, type ScanHost,
} from "./engine";
import { analyseAdvisory, fallbackProfile } from "./profile";
import { investigateHost } from "./investigate";
import { mitigationsFromPlan, planRemediation } from "./plan";
import { proposeFixesFor } from "./workflow";
import {
  CVE_RE, fixStatusFor, htmlToText, idsOnPage, judgmentSummary, linksOnPage, matchSourcePackage, naiveVerdictFor,
  type FixStatus,
} from "./judgecore";
import { clip, mapPool } from "./util";

const HOST_CONCURRENCY = 3;

/** Stored alongside the judgment (not part of the API contract): what tracking needs later. */
interface JudgmentInternal {
  evidence: Record<string, Evidence>;
  exposedPorts: Record<string, { port: number; protocol: "tcp" | "udp" }[]>;
  candidate: { aliases: string[]; title: string; cvss: string | null };
}

// ---------------------------------------------------------------- queue + cancellation
class JudgmentCancelled extends Error {
  constructor() { super("judgment cancelled by an environment reset"); this.name = "JudgmentCancelled"; }
}
let generation = 0;
const queue: string[] = [];
let running = false;

/** Full reset: stop running/queued judgments; nothing they compute afterwards is persisted or audited. */
export function cancelJudgments(): number {
  generation++;
  const n = queue.length + (running ? 1 : 0);
  queue.length = 0;
  running = false; // release the slot now (like cancelScan); the cancelled job never writes again
  return n;
}

function pump() {
  if (running) return;
  const id = queue.shift();
  if (!id) return;
  running = true;
  const gen = generation;
  runJob(id, gen)
    .catch((e) => console.error("[judge]", e))
    .finally(() => { if (gen === generation) { running = false; pump(); } });
}

export function validCve(x: unknown): string | null {
  if (typeof x !== "string" || !x.trim()) return null;
  const c = x.trim().toUpperCase();
  if (!CVE_RE.test(c)) throw new HttpError(400, `"${clip(x, 40)}" is not a CVE id (CVE-YYYY-NNNN)`);
  return c;
}

export function validAdvisoryUrl(x: unknown): string {
  if (typeof x !== "string" || !x.trim()) throw new HttpError(400, "url required");
  const s = x.trim();
  if (s.length > 2000) throw new HttpError(400, "url too long (max 2000 characters)");
  let u: URL;
  try { u = new URL(s); } catch { throw new HttpError(400, "url is not a valid URL"); }
  if (u.protocol !== "https:") throw new HttpError(400, "only https:// advisory URLs are allowed");
  return u.toString();
}

export async function startJudgment(input: { url: string; cveId?: string | null; focus?: string | null; threadId?: string | null; actor: string }): Promise<AdvisoryJudgment> {
  const url = validAdvisoryUrl(input.url);
  try { await assertPublicUrl(url); } catch (e) { throw new HttpError(400, (e as Error).message); } // fail fast; re-checked on every fetch hop
  const cveId = validCve(input.cveId ?? null);
  const focus = typeof input.focus === "string" && input.focus.trim() ? input.focus.trim().slice(0, 300) : null;
  const now = nowIso();
  const j: AdvisoryJudgment = {
    id: newId("jdg"), url, focus, requestedBy: input.actor, threadId: input.threadId ?? null, createdAt: now, updatedAt: now,
    state: "queued", progress: running || queue.length ? "Queued behind another judgment" : "Queued", error: null,
    advisory: null, profile: null, hosts: [], notInstalledOn: [], summary: null, tracked: null,
  };
  saveJudgment(j, cveId ? { requestedCve: cveId } : undefined);
  audit("judgment_requested", `${input.actor} asked Sentinel to judge an advisory: ${clip(url, 200)}${cveId ? ` (${cveId})` : ""}${focus ? ` — focus: ${clip(focus, 80)}` : ""}`, {
    actor: input.actor, ...(cveId ? { cveId } : {}), data: { judgmentId: j.id, url, focus, threadId: j.threadId },
  });
  queue.push(j.id);
  pump();
  return j;
}

// ---------------------------------------------------------------- the job
async function runJob(id: string, gen: number) {
  const live = () => { if (gen !== generation) throw new JudgmentCancelled(); };
  const j = getJudgment(id);
  if (!j) return;
  const requestedCve = getJudgmentInternal<{ requestedCve?: string }>(id)?.requestedCve ?? null;
  const step = (state: AdvisoryJudgment["state"], progress: string, internal?: unknown) => {
    live();
    j.state = state; j.progress = progress; j.updatedAt = nowIso();
    saveJudgment(j, internal);
  };
  const t0 = Date.now();
  try {
    // 1) fetch the page (SSRF-safe)
    step("fetching", `Fetching ${new URL(j.url).hostname}`);
    const res = await safeFetch(j.url);
    live();
    if (res.status >= 400) throw new Error(`the advisory page returned HTTP ${res.status}`);
    const isHtml = /html/i.test(res.contentType) || /^\s*</.test(res.body);
    const text = isHtml ? htmlToText(res.body) : res.body;
    if (text.trim().length < 80) throw new Error("the page has almost no readable text (it may need JavaScript, or block automated readers)");
    const links = isHtml ? linksOnPage(res.body, res.url) : [...new Set(text.match(/https:\/\/[^\s"'<>()\[\]\\]+/g) ?? [])].slice(0, 30);
    const ids = idsOnPage(text);

    // 2) extract the focal vulnerability, consult distro records, build the threat profile
    step("analysing", "Reading the advisory");
    const ex = await extractJudgment(`judge-${id}-extract`, { url: res.url, text }, j.focus);
    live();
    const exCve = ex.cveId && CVE_RE.test(ex.cveId.trim().toUpperCase()) ? ex.cveId.trim().toUpperCase() : null;
    // the extractor's id only counts if the page really states it (models hallucinate plausible ids)
    const cveId = requestedCve ?? (exCve && ids.includes(exCve) ? exCve : null);
    let ubuntu: OsvVuln | null = null, debian: OsvVuln | null = null, cveRec: OsvVuln | null = null;
    if (cveId) {
      step("analysing", `Checking distribution records for ${cveId}`);
      [ubuntu, debian, cveRec] = await Promise.all([
        getVuln(`UBUNTU-${cveId}`).catch(() => null), getVuln(`DEBIAN-${cveId}`).catch(() => null), getVuln(cveId).catch(() => null),
      ]);
      live();
    }
    const exRanges: VersionRange[] = (ex.affectedRanges ?? []).filter((r) => r.introduced || r.fixed || r.lastAffected);
    const ranges = exRanges.length ? exRanges : upstreamRanges(cveRec);
    j.advisory = {
      cveId,
      otherIds: ids.filter((x) => x !== cveId),
      title: clip(ex.title || cveRec?.summary || "Advisory", 200),
      product: clip(ex.product, 120),
      sourcePackageGuess: clip(ex.sourcePackageGuess, 80),
      affectedRanges: ranges,
      fixedVersions: ex.fixedVersions ?? [],
      fixAvailable: ex.fixAvailable,
      conditions: (ex.conditions ?? []).slice(0, 10),
      distroRecords: [ubuntu?.id, debian?.id].filter(Boolean) as string[],
      onIgnoreList: !!cveId && env.ignoreCves.includes(cveId),
    };

    const hosts = loadHosts();
    const matched: { h: ScanHost; source: string; reason: string }[] = [];
    j.notInstalledOn = [];
    for (const h of hosts) {
      const m = matchSourcePackage(sourcesOf(h.inv), ex.sourcePackageGuess, ex.packageAliases ?? []);
      if (m) matched.push({ h, source: m.source, reason: m.reason });
      else j.notInstalledOn.push({ hostId: h.id, hostName: h.name });
    }
    const c = candidateFor(id, j, ex, text, links, { ubuntu, debian, cveRec }, [...new Set(matched.map((m) => m.source))], ranges);
    const bins = [...new Set(matched.flatMap((m) => sourcesOf(m.h.inv).get(m.source)?.binaries.map((b) => b.name) ?? []))].sort();
    const hostsContext = matched.length ? `${c.sourcePkgs.join(", ")} (installed binaries: ${bins.join(", ") || "n/a"})` : "not installed on any monitored host";

    step("analysing", "Building the threat profile");
    let profile: ThreatProfile;
    try {
      profile = await analyseAdvisory(`judge-${id}-profile`, c, hostsContext, { url: res.url, text, focus: j.focus });
    } catch (e) {
      live();
      profile = { ...fallbackProfile(c), summary: clip(ex.title + ". " + (ex.conditions ?? []).join("; "), 600), sources: [res.url] };
      console.warn(`[judge] ${id}: advisory analysis failed, minimal profile used: ${(e as Error).message}`);
    }
    live();
    c.profile = profile;
    j.profile = profile;

    // 3) per-host evidence → the scan's investigator + guardrails → planner
    const work = matched.map(({ h, source, reason }) => ({ h, reason, ...evidenceFor(h, source, c, ranges, ex.fixedVersions ?? []) }));
    step("investigating", work.length ? `Investigating ${work.length} host(s)` : "No host has the affected package");
    let done = 0;
    const results = await mapPool(work, HOST_CONCURRENCY, async ({ h, e, fix, reason }) => {
      live();
      const k = await investigateHost(`judge-${id}-${h.id}`, c, e, profile);
      live();
      if (k.status !== "not_affected") {
        const { plan } = await planRemediation(`judge-${id}-${h.id}-plan`, c, k, profile);
        live();
        k.investigation.remediationPlan = plan;
        k.mitigations = mitigationsFromPlan(plan);
      }
      done++;
      step("investigating", `Investigated ${h.name} (${done}/${work.length})`);
      return { k, fix, reason };
    });

    j.hosts = results.map(({ k, fix, reason }) => judgmentHost(k, fix, reason));
    j.summary = judgmentSummary({ title: j.advisory.title, cveId, hostsTotal: hosts.length, hosts: j.hosts, fixAvailable: ex.fixAvailable });
    const internal: JudgmentInternal = {
      evidence: Object.fromEntries(results.map(({ k }) => [k.evidence.hostId, k.evidence])),
      exposedPorts: Object.fromEntries(results.map(({ k }) => [k.evidence.hostId, k.exposedPorts])),
      candidate: { aliases: c.aliases, title: c.title, cvss: c.cvss },
    };
    step("done", `Done in ${Math.round((Date.now() - t0) / 1000)}s`, internal);
    const counts = countsOf(j.hosts);
    audit("judgment_done", `Sentinel judged "${clip(j.advisory.title, 100)}"${cveId ? ` (${cveId})` : ""}: ${counts.exposed} exposed, ${counts.vulnerable_not_exposed} vulnerable but unreachable, ${counts.not_affected} not affected, ${j.notInstalledOn.length} without the package`, {
      ...(cveId ? { cveId } : {}), data: { judgmentId: id, url: j.url, counts, notInstalled: j.notInstalledOn.length, naiveVulnerable: j.hosts.filter((x) => x.naiveVerdict === "vulnerable").length },
    });
  } catch (e) {
    if (e instanceof JudgmentCancelled || gen !== generation) return;
    j.state = "failed";
    j.error = clip((e as Error).message || "judgment failed", 500);
    j.progress = "Failed";
    j.updatedAt = nowIso();
    saveJudgment(j);
    audit("judgment_done", `Judging ${clip(j.url, 160)} failed: ${clip(j.error, 200)}`, { data: { judgmentId: id, url: j.url, error: j.error } });
  }
}

function countsOf(hosts: JudgmentHost[]) {
  const c = { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 };
  for (const h of hosts) c[h.status]++;
  return c;
}

function candidateFor(
  id: string, j: AdvisoryJudgment, ex: JudgmentExtraction, pageText: string, links: string[],
  recs: { ubuntu: OsvVuln | null; debian: OsvVuln | null; cveRec: OsvVuln | null }, sourcePkgs: string[], ranges: VersionRange[],
): Candidate {
  const cveId = j.advisory!.cveId;
  const cve = cveId ?? `ADV-${id}`;
  const ke = cveId ? kevEntry(cveId) : null;
  const sev = bestSeverity([recs.ubuntu, recs.debian, recs.cveRec]);
  // aliases only from records about THIS CVE (ids elsewhere on the page may belong to other bugs)
  const aliases = new Set<string>();
  for (const r of [recs.cveRec, recs.ubuntu, recs.debian]) if (r) for (const x of allIds(r)) aliases.add(x);
  aliases.delete(cve);
  return {
    cve,
    sourcePkgs,
    aliases: [...aliases].sort(),
    title: j.advisory!.title,
    summary: clip([ex.title, ex.product && `Product: ${ex.product}`, ex.conditions?.length ? `Conditions: ${ex.conditions.join("; ")}` : ""].filter(Boolean).join("\n"), 800),
    details: clip(pageText, 3000),
    kev: !!ke,
    kevInfo: ke,
    cvss: sev.vector ? (sev.score !== null ? `${sev.score} ${sev.vector}` : sev.vector) : null,
    cvssScore: sev.score,
    severityLabel: sev.label,
    upstreamRanges: ranges,
    // the analyst's fetch allow-list = the page itself + the links on it (still subject to safe fetch)
    cveRecord: { id: cve, references: [{ type: "ADVISORY", url: j.url }, ...links.map((url) => ({ type: "WEB", url }))] },
    distroRecords: { UBUNTU: recs.ubuntu, DEBIAN: recs.debian },
    textOnly: { product: ex.product, sourcePackageGuess: ex.sourcePackageGuess, affectedRanges: ranges, fixedVersions: ex.fixedVersions ?? [], conditions: ex.conditions ?? [] },
    reason: "admin asked Sentinel to judge this advisory",
    triage: { decidedBy: "sentinel", reason: "admin asked Sentinel to judge this advisory" },
    profile: null,
  };
}

/** Deterministic per-host facts. Not buildEvidence: in a scan "record exists but OSV didn't match" means patched;
 *  here nothing was matched, so the fix status comes from fixStatusFor alone. */
export function evidenceFor(h: ScanHost, source: string, c: Candidate, ranges: VersionRange[], upstreamFixed: string[]): { e: Evidence; fix: FixStatus } {
  const s = sourcesOf(h.inv).get(source)!;
  const eco = ecosystemFor(h.inv.os);
  const key = eco?.startsWith("Debian") ? "DEBIAN" : "UBUNTU";
  const fix = fixStatusFor({
    installed: s.version, ecosystem: eco, source, record: c.distroRecords[key] ?? null, recordLabel: key === "DEBIAN" ? "Debian" : "Ubuntu",
    ranges, upstreamFixed,
  });
  const e: Evidence = {
    hostId: h.id,
    hostName: h.name,
    sourcePackage: source,
    binaries: s.binaries.map((b) => b.name),
    binaryVersions: s.binaries.map((b) => `${b.name}=${b.version}`),
    installedVersion: s.version,
    upstreamVersion: upstreamVersion(s.version),
    distroVerdict: fix.source === "distro_record" ? fix.verdict : "unknown",
    distroFixed: fix.distroFixed,
    installedVsFixed: fix.detail,
    naiveVerdict: naiveVerdictFor(s.version, ranges),
    listening: externalListeners(h.inv).map(fmtListener),
    firewall: firewallText(h.inv),
    closedPorts: [...closedPortsOf(h.inv)].sort(),
    inKev: c.kev,
    cvss: c.cvss,
    needsConfirmation: fix.source === "advisory_only",
    factsDigest: factsDigestOf(h.inv, source, s.binaries),
    fixSource: fix.source,
  };
  return { e, fix };
}

function judgmentHost(k: Classified, fix: FixStatus, reason: string): JudgmentHost {
  const e = k.evidence;
  return {
    hostId: e.hostId,
    hostName: e.hostName,
    sourcePackage: e.sourcePackage!,
    installedVersion: e.installedVersion!,
    upstreamVersion: e.upstreamVersion!,
    binaries: e.binaries,
    packageMatch: reason,
    fixStatus: { source: fix.source, verdict: fix.verdict, fixedVersion: fix.fixedVersion, detail: fix.detail },
    naiveVerdict: e.naiveVerdict,
    status: k.status,
    priority: k.priority,
    confidence: k.confidence,
    needsConfirmation: k.needsConfirmation,
    rationale: k.rationale,
    reachability: k.reachability,
    exposedPorts: k.exposedPorts.map((p) => `${p.port}/${p.protocol}`),
    mitigations: k.mitigations,
    investigation: k.investigation,
  };
}

// ---------------------------------------------------------------- Track as findings
export function trackJudgment(id: string, input: { cveId?: unknown; actor: string }): AdvisoryJudgment {
  const j = getJudgment(id);
  if (!j) throw new HttpError(404, "judgment not found");
  if (j.state !== "done") throw new HttpError(409, `judgment is ${j.state}; only finished judgments can be tracked`);
  if (j.tracked) throw new HttpError(409, `already tracked as ${j.tracked.cveId} by ${j.tracked.by}`);
  const bodyCve = validCve(input.cveId);
  // the body may only supply a CVE when the judgment has none: the evidence was judged against THIS CVE's records
  if (bodyCve && j.advisory?.cveId && bodyCve !== j.advisory.cveId) throw new HttpError(409, `this judgment is about ${j.advisory.cveId}; it cannot be tracked as ${bodyCve}`);
  const cve = j.advisory?.cveId ?? bodyCve;
  if (!cve) throw new HttpError(409, "this advisory has no CVE id; findings need one — pass { cveId: \"CVE-YYYY-NNNN\" } once a CVE is assigned");
  const internal = getJudgmentInternal<JudgmentInternal>(id);
  if (!internal?.evidence || !j.profile) throw new HttpError(409, "judgment has no stored evidence to track");

  const now = nowIso();
  const ke = kevEntry(cve);
  const sameCve = cve === j.advisory?.cveId;
  const reason = `tracked from advisory judgment ${id} by ${input.actor}`;
  const cand = {
    cve, aliases: sameCve ? internal.candidate.aliases.filter((x) => x !== cve) : [], title: internal.candidate.title,
    kev: !!ke, kevInfo: ke, cvss: internal.candidate.cvss, triage: { decidedBy: "sentinel" as const, reason },
  };
  const profile: ThreatProfile = { ...j.profile, cveId: cve };
  const hadFindingsBefore = listFindings({ cveId: cve }).length > 0;
  const written: Finding[] = [];
  for (const h of j.hosts) {
    const stored = internal.evidence[h.hostId];
    if (!stored) continue;
    const e: Evidence = { ...stored, inKev: !!ke };
    const k: Classified = {
      cve, evidence: e, status: h.status, priority: h.status === "exposed" && ke ? "critical" : h.priority, confidence: h.confidence,
      rationale: h.rationale, mitigations: h.mitigations, needsConfirmation: h.needsConfirmation,
      evidenceHash: evidenceHash(e, profile.generatedAt),
      investigation: { ...h.investigation, triage: cand.triage }, reachability: h.reachability,
      exposedPorts: internal.exposedPorts[h.hostId] ?? [],
    };
    const prev = getFindingByKey(e.hostId, cve)?.finding;
    const f = buildFinding(cand, k, prev, now);
    saveFinding(f, k.evidenceHash);
    written.push(f);
    if (f.status !== "not_affected" && prev?.status !== f.status) {
      audit("vulnerable_detected", `${e.hostName} assessed ${statusLabel(f.status)} for ${cve}: ${e.sourcePackage} ${e.installedVersion}, ${f.status === "exposed" ? "reachable from the network" : "no network path to the vulnerable component"}.`, {
        hostId: f.hostId, cveId: cve, actor: input.actor, data: { findingId: f.id, status: f.status, priority: f.priority, from: prev?.status ?? null, judgmentId: id },
      });
    }
    if (!prev) audit("finding_new", `${e.hostName} · ${cve}: ${statusLabel(f.status)} (${priorityLabel(f.priority)})`, { hostId: f.hostId, cveId: cve, actor: input.actor, data: { findingId: f.id, judgmentId: id } });
    else if (prev.status !== f.status || prev.priority !== f.priority) {
      audit("finding_changed", `${e.hostName} · ${cve}: ${statusLabel(prev.status)} → ${statusLabel(f.status)} (${priorityLabel(f.priority)})`, { hostId: f.hostId, cveId: cve, actor: input.actor, data: { findingId: f.id, from: prev.status, judgmentId: id } });
    }
  }
  if (!hadFindingsBefore && written.length) {
    audit("cve_discovered", `New vulnerability: ${cve} — ${cand.title}${cand.cvss ? ` (CVSS ${cand.cvss.split(" ")[0]})` : ""}${cand.kev ? ", listed in CISA KEV" : ""}. Tracked from an advisory judgment.`, {
      cveId: cve, actor: input.actor, data: { kev: cand.kev, reason, judgmentId: id },
    });
  }
  saveProfile(profile);
  saveTriage({ cveId: cve, decision: "investigate", decidedBy: "sentinel", reason });
  // same proposal rules as the scan: containment only if exposed (validated plan action), upgrade only with a fixed build
  const notes: string[] = [];
  let proposed = 0;
  for (const f of written) proposed += proposeFixesFor(f, notes);
  for (const n of notes) console.warn(`[judge] ${id}: ${n}`);
  j.tracked = { at: now, by: input.actor, cveId: cve, findingIds: written.map((f) => f.id), proposedActions: proposed };
  j.updatedAt = now;
  saveJudgment(j); // sets tracked_cve → scans stop ignoring this CVE (heldSet)
  audit("judgment_tracked", `${input.actor} tracked the advisory judgment of ${cve} as findings: ${written.length} finding(s), ${proposed} proposal(s)`, {
    cveId: cve, actor: input.actor, data: { judgmentId: id, findingIds: j.tracked.findingIds, proposedActions: proposed },
  });
  return j;
}

/** Compact view for chat tools (the web chat renders a live card for any tool output whose id starts with jdg_). */
export function slimJudgment(j: AdvisoryJudgment) {
  return {
    id: j.id, url: j.url, state: j.state, progress: j.progress, error: j.error, advisory: j.advisory, summary: j.summary,
    tracked: j.tracked, notInstalledOn: j.notInstalledOn,
    hosts: j.hosts.map((h) => ({
      hostId: h.hostId, hostName: h.hostName, status: h.status, priority: h.priority, confidence: h.confidence,
      needsConfirmation: h.needsConfirmation, fixStatus: h.fixStatus, naiveVerdict: h.naiveVerdict, reachability: h.reachability,
      rationale: h.rationale, packageMatch: h.packageMatch,
    })),
  };
}
