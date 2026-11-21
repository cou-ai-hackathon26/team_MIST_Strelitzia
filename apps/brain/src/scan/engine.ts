// Deterministic scan logic (data gathering, evidence, hard rules). AI steps live in ./ai.ts.
import type { Finding, FindingStatus, InstalledPackage, InventorySnapshot, Investigation, Priority, ThreatProfile } from "@prohori/shared";
import { getFindingByKey, getInventory, holdState, listHostRows, sha256, updateHostMeta } from "../db";
import { inKev, kevEntry } from "../vuln/kev";
import {
  allIds, cveOf, distroFixed, ecosystemFor, getVuln, getVulns, queryBatch, severityOf, upstreamRanges, type OsvVuln,
} from "../vuln/osv";
import { compareDebian, inAnyRange, upstreamVersion, type VersionRange } from "../vuln/versions";

export interface ScanHost {
  id: string;
  name: string;
  inv: InventorySnapshot;
  ecosystem: string | null;
}

export interface AdvisoryExtraction {
  product: string;
  sourcePackageGuess: string;
  affectedRanges: { introduced?: string; fixed?: string }[];
  fixedVersions: string[];
  conditions: string[];
}

export interface Candidate {
  cve: string;
  sourcePkgs: string[];
  aliases: string[];
  title: string;
  summary: string;
  details: string;
  kev: boolean;
  kevInfo: ReturnType<typeof kevEntry>;
  cvss: string | null;
  cvssScore: number | null;
  severityLabel: string | null;
  upstreamRanges: VersionRange[];
  cveRecord: OsvVuln | null;
  distroRecords: Record<string, OsvVuln | null>; // "UBUNTU" | "DEBIAN"
  textOnly: AdvisoryExtraction | null;
  reason: string; // why triage selected it
  triage: { decidedBy: "rule" | "sentinel"; reason: string };
  profile: ThreatProfile | null;
}

/** Deterministic, product-agnostic facts about one (host, CVE) pair. Sentinel's investigation builds on these. */
export interface Evidence {
  hostId: string;
  hostName: string;
  sourcePackage: string | null;
  binaries: string[];
  binaryVersions: string[];
  installedVersion: string | null;
  upstreamVersion: string | null;
  distroVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  distroFixed: string | null;
  installedVsFixed: string;
  naiveVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  listening: string[];
  firewall: string;
  closedPorts: string[];
  inKev: boolean;
  cvss: string | null;
  needsConfirmation: boolean;
  factsDigest: string;
}

export interface Classified {
  cve: string;
  evidence: Evidence;
  status: FindingStatus;
  priority: Priority;
  confidence: "high" | "medium" | "low";
  rationale: string;
  mitigations: string[];
  needsConfirmation: boolean;
  evidenceHash: string;
  investigation: Investigation;
  reachability: string;
  exposedPorts: { port: number; protocol: "tcp" | "udp" }[];
  /** true when the finding was reused unchanged from the previous scan (evidence-hash cache hit) */
  cached?: boolean;
}

export interface ScanContext {
  scanId: string;
  sessionId: string;
  trigger: string;
  startedAt: string;
  hosts: ScanHost[];
  /** per host: source → { version, ids (non-held OSV ids) } */
  matches: Map<string, Map<string, { version: string; ids: string[] }>>;
  rawMatchCount: Record<string, number>;
  details: Map<string, OsvVuln | null>;
  /** Sentinel's triage of every matched CVE this scan: cve → decision */
  triage: Map<string, { decision: "investigate" | "ignore"; decidedBy: "rule" | "sentinel"; reason: string; cached: boolean }>;
  candidates: Candidate[];
  evidence: Map<string, Evidence[]>; // cve → evidence per host
  classified: Classified[];
  newFindings: Finding[];
  changedFindings: Finding[];
  /** new or changed findings whose severity went UP into exposed / vulnerable_not_exposed (these trigger a report) */
  escalated: Finding[];
  reportId: string | null;
  reportsSent: number;
  proposedActions: number;
  notes: string[];
}

// ---------------------------------------------------------------- hold
export function heldSet(): Set<string> {
  return new Set(holdState().held.map((s) => s.toUpperCase()));
}
export function isHeldVuln(v: OsvVuln | null, id: string, held: Set<string>): boolean {
  if (!held.size) return false;
  if (held.has(id.toUpperCase())) return true;
  if (!v) {
    const m = id.toUpperCase().match(/(CVE-\d{4}-\d+)$/);
    return !!m && held.has(m[1]!);
  }
  const cve = cveOf(v);
  if (cve && held.has(cve)) return true;
  return allIds(v).some((x) => held.has(x));
}

// ---------------------------------------------------------------- a. load
export function loadHosts(): ScanHost[] {
  const out: ScanHost[] = [];
  for (const h of listHostRows()) {
    const inv = getInventory(h.id);
    if (!inv) continue;
    out.push({ id: h.id, name: h.name, inv, ecosystem: ecosystemFor(inv.os) });
  }
  return out;
}

/** source → installed version (from the first binary of that source) */
export function sourcesOf(inv: InventorySnapshot): Map<string, { version: string; binaries: InstalledPackage[] }> {
  const m = new Map<string, { version: string; binaries: InstalledPackage[] }>();
  for (const p of inv.packages) {
    const src = (p.source || p.name).replace(/\s*\(.*\)$/, "");
    const e = m.get(src);
    if (e) e.binaries.push(p);
    else m.set(src, { version: p.version, binaries: [p] });
  }
  return m;
}

// ---------------------------------------------------------------- b. OSV match
export async function osvMatch(ctx: ScanContext) {
  const held = heldSet();
  const allMatchedIds: string[] = [];
  for (const h of ctx.hosts) {
    const perHost = new Map<string, { version: string; ids: string[] }>();
    ctx.matches.set(h.id, perHost);
    if (!h.ecosystem) {
      ctx.notes.push(`${h.name}: unsupported OS for OSV (${h.inv.os?.name})`);
      continue;
    }
    const srcs = [...sourcesOf(h.inv).entries()];
    const queries = srcs.map(([name, s]) => ({ name, version: s.version, ecosystem: h.ecosystem! }));
    const res: string[][] = [];
    for (let i = 0; i < queries.length; i += 500) res.push(...(await queryBatch(queries.slice(i, i + 500))));
    srcs.forEach(([name, s], i) => {
      const ids = res[i] ?? [];
      if (ids.length) perHost.set(name, { version: s.version, ids });
      allMatchedIds.push(...ids);
    });
  }
  ctx.details = await getVulns(allMatchedIds);
  for (const h of ctx.hosts) {
    let n = 0;
    for (const [, m] of ctx.matches.get(h.id) ?? []) {
      m.ids = m.ids.filter((id) => !isHeldVuln(ctx.details.get(id) ?? null, id, held));
      n += m.ids.length;
    }
    ctx.rawMatchCount[h.id] = n;
    updateHostMeta(h.id, { rawMatchCount: n });
  }
}

// ---------------------------------------------------------------- c. matched CVEs (input to Sentinel's triage)
export interface MatchedCve {
  cve: string;
  sources: Set<string>;
  hosts: Set<string>;
  records: OsvVuln[];
}

/** Group the (non-held) raw OSV matches by CVE id. */
export function matchedCves(ctx: ScanContext): Map<string, MatchedCve> {
  const byCve = new Map<string, MatchedCve>();
  for (const [hostId, perHost] of ctx.matches) {
    for (const [src, m] of perHost) {
      for (const id of m.ids) {
        const v = ctx.details.get(id) ?? null;
        const cve = v ? cveOf(v) : (id.match(/(CVE-\d{4}-\d+)$/)?.[1] ?? null);
        if (!cve) continue;
        const e = byCve.get(cve) ?? { cve, sources: new Set<string>(), hosts: new Set<string>(), records: [] };
        e.sources.add(src);
        e.hosts.add(hostId);
        if (v && !e.records.some((r) => r.id === v.id)) e.records.push(v);
        byCve.set(cve, e);
      }
    }
  }
  return byCve;
}

/** Best severity across a CVE's matched records (distro label preferred, then the highest CVSS score). */
export function bestSeverity(records: (OsvVuln | null)[]) {
  const sevs = records.map((r) => severityOf(r));
  const best = sevs.reduce((a, b) => ((b.score ?? -1) > (a.score ?? -1) ? b : a), { score: null, vector: null, label: null } as ReturnType<typeof severityOf>);
  return { score: best.score, vector: best.vector ?? sevs.find((s) => s.vector)?.vector ?? null, label: sevs.find((s) => s.label)?.label ?? null };
}

/** Hard floor of the triage: these are always investigated, whatever the AI thinks. */
export function floorRule(cve: string, records: (OsvVuln | null)[]): string | null {
  if (inKev(cve)) return "on CISA KEV (known exploited)";
  if (bestSeverity(records).label === "critical") return "distro priority critical";
  return null;
}

/** Full candidate records for the CVEs triage chose (plus re-checks of open findings). */
export async function buildCandidates(ctx: ScanContext, chosen: Map<string, { sources: Set<string>; decidedBy: "rule" | "sentinel"; reason: string }>) {
  const held = heldSet();
  for (const [cve, { sources, decidedBy, reason }] of chosen) {
    const [cveRec, ubuntu, debian] = await Promise.all([getVuln(cve), getVuln(`UBUNTU-${cve}`), getVuln(`DEBIAN-${cve}`)]);
    if (isHeldVuln(cveRec, cve, held)) continue;
    const ke = kevEntry(cve);
    const sev = bestSeverity([ubuntu, debian, cveRec]);
    const aliases = new Set<string>();
    for (const r of [cveRec, ubuntu, debian]) if (r) for (const id of allIds(r)) aliases.add(id);
    aliases.delete(cve);
    ctx.candidates.push({
      cve,
      sourcePkgs: [...sources],
      aliases: [...aliases].sort(),
      title: ke?.vulnerabilityName ?? cveRec?.summary ?? ubuntu?.summary ?? cve,
      summary: cveRec?.summary ?? ubuntu?.summary ?? "",
      details: (cveRec?.details ?? ubuntu?.details ?? debian?.details ?? "").slice(0, 4000),
      kev: !!ke,
      kevInfo: ke,
      cvss: sev.vector ? (sev.score !== null ? `${sev.score} ${sev.vector}` : sev.vector) : null,
      cvssScore: sev.score,
      severityLabel: sev.label,
      upstreamRanges: upstreamRanges(cveRec),
      cveRecord: cveRec,
      distroRecords: { UBUNTU: ubuntu, DEBIAN: debian },
      textOnly: null,
      reason,
      triage: { decidedBy, reason },
      profile: null,
    });
  }
}

/** True if a candidate has neither distro records nor structured upstream ranges → needs the text-only AI path. */
export function needsTextPath(c: Candidate): boolean {
  return !c.distroRecords.UBUNTU && !c.distroRecords.DEBIAN && c.upstreamRanges.length === 0;
}

// ---------------------------------------------------------------- d. cross-host facts (deterministic, product-agnostic)
export const isLoopback = (addr: string) => addr.startsWith("127.") || addr === "::1" || addr === "localhost";

export function closedPortsOf(inv: InventorySnapshot): Set<string> {
  return new Set((inv.firewall?.closedPorts ?? []).map((r) => `${r.port}/${r.protocol ?? "tcp"}`));
}

export function firewallText(inv: InventorySnapshot): string {
  const closed = closedPortsOf(inv);
  return closed.size
    ? [...closed].map((c) => `${c} closed by Sentinel firewall rule`).join(", ")
    : (inv.firewall?.available === false ? "firewall tooling unavailable; no rules" : "no Sentinel firewall rules");
}

export interface ListenerFact { address: string; port: number; protocol: string; process: string; blocked: boolean }

export function externalListeners(inv: InventorySnapshot): ListenerFact[] {
  const closed = closedPortsOf(inv);
  const seen = new Set<string>();
  const out: ListenerFact[] = [];
  for (const p of inv.listeningPorts ?? []) {
    if (isLoopback(p.address)) continue;
    const protocol = p.protocol ?? "tcp";
    const k = `${p.address}:${p.port}/${protocol}:${p.process}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ address: p.address, port: p.port, protocol, process: p.process, blocked: closed.has(`${p.port}/${protocol}`) });
  }
  return out.sort((a, b) => a.port - b.port);
}

/**
 * Listeners whose process name obviously belongs to the source package (process name equals one of its binary
 * package names, or contains the package-name stem). Used only to detect contradictions with Sentinel's
 * "not reachable" conclusion — never to conclude "not reachable" by itself.
 */
export function obviouslyOwnedListeners(src: string, binaries: string[], inv: InventorySnapshot): ListenerFact[] {
  const stem = src.replace(/[\d.\-]+$/, "").toLowerCase();
  const names = new Set(binaries.map((b) => b.toLowerCase()));
  return externalListeners(inv).filter((l) => {
    const p = l.process.toLowerCase();
    return names.has(p) || (stem.length >= 3 && p.includes(stem));
  });
}

const fmtListener = (l: ListenerFact) => `${l.address}:${l.port}/${l.protocol} ${l.process}${l.blocked ? " (blocked by firewall)" : ""}`;

/** Digest of the host facts that can change a verdict (cache key for the investigation). */
function hostFactsDigest(inv: InventorySnapshot, src: string, binaries: InstalledPackage[]) {
  return {
    binaries: binaries.map((b) => `${b.name}=${b.version}`).sort(),
    listeners: externalListeners(inv).map(fmtListener),
    loopback: [...new Set((inv.listeningPorts ?? []).filter((p) => isLoopback(p.address)).map((p) => `${p.port}/${p.protocol ?? "tcp"} ${p.process}`))].sort(),
    processes: [...new Set((inv.processes ?? []).map((p) => p.name))].sort(),
    firewall: [...closedPortsOf(inv)].sort(),
    config: Object.entries(inv.config ?? {}).map(([k, v]) => `${k}=${v}`).sort(),
    src,
  };
}

export function buildEvidence(ctx: ScanContext, c: Candidate): Evidence[] {
  const out: Evidence[] = [];
  for (const h of ctx.hosts) {
    const srcs = sourcesOf(h.inv);
    const matches = ctx.matches.get(h.id) ?? new Map();
    // the source of this CVE on this host: prefer one OSV matched with this CVE, else any candidate source installed
    let src: string | null = null;
    let distroMatched = false;
    for (const [s, m] of matches) {
      if (m.ids.some((id: string) => { const v = ctx.details.get(id); return (v ? cveOf(v) : id.replace(/^(UBUNTU|DEBIAN)-/, "")) === c.cve; })) {
        src = s; distroMatched = true; break;
      }
    }
    if (!src) src = c.sourcePkgs.find((s) => srcs.has(s)) ?? null;
    if (!src && c.textOnly) {
      const guess = c.textOnly.sourcePackageGuess.toLowerCase();
      src = [...srcs.keys()].find((s) => s === guess || s.startsWith(guess)) ?? null;
    }
    if (!src) continue; // product not installed on this host — nothing to say
    const s = srcs.get(src)!;
    const up = upstreamVersion(s.version);
    const distroKey = h.ecosystem?.startsWith("Debian") ? "DEBIAN" : "UBUNTU";
    const df = h.ecosystem ? distroFixed(c.distroRecords[distroKey] ?? null, h.ecosystem, src) : { fixed: null, hasRecord: false };

    let distroVerdict: Evidence["distroVerdict"] = "unknown";
    if (distroMatched) distroVerdict = "vulnerable";
    else if (df.hasRecord) distroVerdict = "not_vulnerable";
    else if (df.fixed) distroVerdict = compareDebian(s.version, df.fixed) >= 0 ? "not_vulnerable" : "vulnerable";

    const ranges: VersionRange[] = c.upstreamRanges.length ? c.upstreamRanges : (c.textOnly?.affectedRanges ?? []);
    const naive: Evidence["naiveVerdict"] = ranges.length ? (inAnyRange(up, ranges) ? "vulnerable" : "not_vulnerable") : "unknown";

    let cmp = "no distro fixed version known";
    if (df.fixed) {
      const d = compareDebian(s.version, df.fixed);
      cmp = d < 0 ? `installed ${s.version} < fixed ${df.fixed} (older than the patched build)` : `installed ${s.version} >= fixed ${df.fixed} (patched build)`;
    }
    const ext = externalListeners(h.inv);
    out.push({
      hostId: h.id,
      hostName: h.name,
      sourcePackage: src,
      binaries: s.binaries.map((b) => b.name),
      binaryVersions: s.binaries.map((b) => `${b.name}=${b.version}`),
      installedVersion: s.version,
      upstreamVersion: up,
      distroVerdict,
      distroFixed: df.fixed,
      installedVsFixed: cmp,
      naiveVerdict: naive,
      listening: ext.map(fmtListener),
      firewall: firewallText(h.inv),
      closedPorts: [...closedPortsOf(h.inv)].sort(),
      inKev: c.kev,
      cvss: c.cvss,
      needsConfirmation: !!c.textOnly || distroVerdict === "unknown",
      factsDigest: sha256(JSON.stringify(hostFactsDigest(h.inv, src, s.binaries))),
    });
  }
  return out;
}

// ---------------------------------------------------------------- g. hard rules
/** Is the installed build in the vulnerable set? (distro verdict wins; unknown errs towards vulnerable) */
export function buildVerdict(e: Evidence): { vulnerable: boolean; uncertain: boolean } {
  const vulnerable = e.distroVerdict === "vulnerable" || (e.distroVerdict === "unknown" && e.naiveVerdict !== "not_vulnerable");
  return { vulnerable, uncertain: e.distroVerdict === "unknown" };
}

export function priorityFor(status: FindingStatus, kev: boolean): Priority {
  if (status === "exposed") return kev ? "critical" : "high";
  if (status === "vulnerable_not_exposed") return "medium";
  return "info";
}

/** Cache key for a (host, CVE) verdict: deterministic facts + the profile version it was investigated against. */
export function evidenceHash(e: Evidence, profileStamp: string | null): string {
  return sha256(JSON.stringify({ e, profileStamp, v: 2 }));
}

/** Deterministic fallback text when the LLM is unavailable. */
export function fallbackRationale(e: Evidence, status: FindingStatus, reachability: string): string {
  const lines = [
    `**${e.hostName}** has \`${e.sourcePackage}\` ${e.installedVersion} (upstream ${e.upstreamVersion}).`,
    `Distro advisory verdict: ${e.distroVerdict} — ${e.installedVsFixed}.`,
    `Reachability: ${reachability}.`,
  ];
  lines.push(
    status === "exposed" ? "Vulnerable build that is reachable from the network → exposed."
      : status === "vulnerable_not_exposed" ? "Vulnerable build but no network path → vulnerable, not exposed."
      : "Installed build is not in the vulnerable set → not affected.",
  );
  return lines.join("\n\n");
}

export function existingFor(hostId: string, cve: string) {
  return getFindingByKey(hostId, cve);
}
