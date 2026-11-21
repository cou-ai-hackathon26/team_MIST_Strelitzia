// Deterministic scan logic (data gathering, evidence, hard rules). AI steps live in ./ai.ts.
import type { Finding, FindingStatus, InstalledPackage, InventorySnapshot, Priority } from "@prohori/shared";
import { getFindingByKey, getInventory, holdState, listFindings, listHostRows, sha256, updateHostMeta } from "../db";
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
  distroRecords: Record<string, OsvVuln | null>; // "UBUNTU" | "DEBIAN"
  textOnly: AdvisoryExtraction | null;
  reason: string; // why it passed the signal filter
}

export interface Evidence {
  hostId: string;
  hostName: string;
  sourcePackage: string | null;
  binaries: string[];
  installedVersion: string | null;
  upstreamVersion: string | null;
  distroVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  distroFixed: string | null;
  installedVsFixed: string;
  naiveVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  reachable: boolean | null;
  reachability: string;
  listening: string[];
  firewall: string;
  exposedPorts: number[];
  webSapi: string[];
  config: Record<string, string>;
  inKev: boolean;
  cvss: string | null;
  needsConfirmation: boolean;
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

// ---------------------------------------------------------------- c. signal filter
/**
 * A CVE becomes a candidate if it is on CISA KEV, or the distro rates it critical, or (no distro rating
 * available) its CVSS v3 base score is >= 9. Distro triage beats raw NVD CVSS when both exist.
 * CVEs with open (non-not_affected) findings are always re-evaluated so they can resolve.
 */
export async function signalFilter(ctx: ScanContext) {
  const held = heldSet();
  const byCve = new Map<string, { sources: Set<string>; reason: string }>();
  for (const [, perHost] of ctx.matches) {
    for (const [src, m] of perHost) {
      for (const id of m.ids) {
        const v = ctx.details.get(id) ?? null;
        const cve = v ? cveOf(v) : (id.match(/(CVE-\d{4}-\d+)$/)?.[1] ?? null);
        if (!cve) continue;
        const sev = severityOf(v);
        let reason = "";
        if (inKev(cve)) reason = "on CISA KEV";
        else if (sev.label === "critical") reason = "distro severity critical";
        else if (!sev.label && sev.score !== null && sev.score >= 9) reason = `CVSS ${sev.score}`;
        if (!reason) continue;
        const e = byCve.get(cve) ?? { sources: new Set<string>(), reason };
        e.sources.add(src);
        byCve.set(cve, e);
      }
    }
  }
  // keep re-evaluating CVEs that still have open findings
  for (const f of listFindings()) {
    if (f.status === "not_affected" || byCve.has(f.cveId) || held.has(f.cveId)) continue;
    byCve.set(f.cveId, { sources: new Set(f.package ? [f.package.name] : []), reason: "re-check of open finding" });
  }

  for (const [cve, { sources, reason }] of byCve) {
    const [cveRec, ubuntu, debian] = await Promise.all([getVuln(cve), getVuln(`UBUNTU-${cve}`), getVuln(`DEBIAN-${cve}`)]);
    if (isHeldVuln(cveRec, cve, held)) continue;
    const ke = kevEntry(cve);
    const sevs = [severityOf(ubuntu), severityOf(debian), severityOf(cveRec)];
    const best = sevs.reduce((a, b) => ((b.score ?? -1) > (a.score ?? -1) ? b : a));
    const vector = best.vector ?? sevs.find((s) => s.vector)?.vector ?? null;
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
      cvss: vector ? (best.score !== null ? `${best.score} ${vector}` : vector) : null,
      cvssScore: best.score,
      severityLabel: sevs.find((s) => s.label)?.label ?? null,
      upstreamRanges: upstreamRanges(cveRec),
      distroRecords: { UBUNTU: ubuntu, DEBIAN: debian },
      textOnly: null,
      reason,
    });
  }
}

/** True if a candidate has neither distro records nor structured upstream ranges → needs the text-only AI path. */
export function needsTextPath(c: Candidate): boolean {
  return !c.distroRecords.UBUNTU && !c.distroRecords.DEBIAN && c.upstreamRanges.length === 0;
}

// ---------------------------------------------------------------- d+f. cross-host evidence
const WEB_SERVERS = /^(nginx|apache2|httpd|caddy|lighttpd|php-fpm.*|php\d.*-fpm.*)$/;
const isLoopback = (addr: string) => addr.startsWith("127.") || addr === "::1" || addr === "localhost";

function closedPortsOf(inv: InventorySnapshot): Set<string> {
  return new Set((inv.firewall?.closedPorts ?? []).map((r) => `${r.port}/${r.protocol ?? "tcp"}`));
}

function reachabilityFor(src: string, binaries: InstalledPackage[], inv: InventorySnapshot) {
  const procs = inv.processes ?? [];
  const closed = closedPortsOf(inv);
  const ports = (inv.listeningPorts ?? []).filter((p) => p.protocol === "tcp" || !p.protocol);
  const externalAll = ports.filter((p) => !isLoopback(p.address));
  const isClosed = (p: { port: number; protocol?: string }) => closed.has(`${p.port}/${p.protocol ?? "tcp"}`);
  const external = externalAll.filter((p) => !isClosed(p));
  const blocked = externalAll.filter(isClosed);
  const fmt = (p: { address: string; port: number; process: string }) => `${p.address}:${p.port} ${p.process}`;
  const fw = closed.size ? [...closed].map((c) => `${c} closed by Sentinel firewall rule`).join(", ") : (inv.firewall?.available === false ? "firewall tooling unavailable; no rules" : "no Sentinel firewall rules");
  const base = { firewall: fw, listening: externalAll.map((p) => fmt(p) + (isClosed(p) ? " (blocked by firewall)" : "")) };
  const portsOf = (ls: typeof externalAll) => [...new Set(ls.map((p) => p.port))];

  if (/^php/.test(src)) {
    const fpmPkgs = binaries.filter((b) => /-fpm$/.test(b.name)).map((b) => b.name);
    const modPhp = inv.packages.filter((p) => /^libapache2-mod-php/.test(p.name)).map((p) => p.name);
    const webSapi = [...fpmPkgs, ...modPhp];
    const fpmRunning = procs.filter((p) => /php.*fpm/.test(p.name)).map((p) => p.name);
    const apacheRunning = modPhp.length ? procs.filter((p) => /^(apache2|httpd)$/.test(p.name)).map((p) => p.name) : [];
    const sapiRunning = [...new Set([...fpmRunning, ...apacheRunning])];
    const webOpen = external.filter((p) => WEB_SERVERS.test(p.process));
    const webBlocked = blocked.filter((p) => WEB_SERVERS.test(p.process));
    const r = (reachable: boolean | null, detail: string, exposedPorts: number[] = []) => ({ ...base, reachable, webSapi, detail, exposedPorts });
    if (!webSapi.length) {
      return r(false, `CLI-only: no web SAPI package installed (${binaries.map((b) => b.name).join(", ")}); PHP is not reachable from the network${externalAll.length ? "" : "; nothing listening on a non-loopback address"}`);
    }
    if (!procs.length) return r(null, `web SAPI installed (${webSapi.join(", ")}) but process list unavailable — reachability unknown`);
    if (!sapiRunning.length) return r(false, `web SAPI installed (${webSapi.join(", ")}) but not running`);
    if (!webOpen.length && webBlocked.length) {
      return r(false, `contained: web SAPI running (${sapiRunning.join(", ")}) behind ${webBlocked.map(fmt).join(", ")}, but ${portsOf(webBlocked).map((p) => `${p}/tcp`).join(", ")} is closed by a Sentinel firewall rule — not reachable from the network (still vulnerable; upgrade to fully fix)`);
    }
    if (!webOpen.length) return r(false, `web SAPI running (${sapiRunning.join(", ")}) but no web server listens on a non-loopback address`);
    return r(true, `web SAPI running (${sapiRunning.join(", ")}) behind ${webOpen.map(fmt).join(", ")} — reachable from the network`, portsOf(webOpen));
  }

  // generic: a listener owned by a process that looks like this package
  const stem = src.replace(/[\d.\-]+$/, "").toLowerCase();
  const owns = (p: { process: string }) => p.process.toLowerCase().includes(stem) || binaries.some((b) => p.process.toLowerCase() === b.name.toLowerCase());
  const own = external.filter(owns);
  if (own.length) return { ...base, reachable: true, webSapi: [], detail: `${src} process listens on ${own.map(fmt).join(", ")}`, exposedPorts: portsOf(own) };
  if (blocked.some(owns)) return { ...base, reachable: false, webSapi: [], detail: `contained: ${src} listeners are blocked by a Sentinel firewall rule (${fw})`, exposedPorts: [] };
  return { ...base, reachable: null, webSapi: [], detail: `no listener owned by ${src}; reachability depends on how the library is used — unknown`, exposedPorts: [] };
}

function relevantConfig(src: string, inv: InventorySnapshot): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(inv.config ?? {})) {
    if (/^php/.test(src) ? /php|nginx/i.test(k) : k.toLowerCase().includes(src.replace(/[\d.\-]+$/, "").toLowerCase())) out[k] = v;
  }
  return out;
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
    const r = reachabilityFor(src, s.binaries, h.inv);
    out.push({
      hostId: h.id,
      hostName: h.name,
      sourcePackage: src,
      binaries: s.binaries.map((b) => b.name),
      installedVersion: s.version,
      upstreamVersion: up,
      distroVerdict,
      distroFixed: df.fixed,
      installedVsFixed: cmp,
      naiveVerdict: naive,
      reachable: r.reachable,
      reachability: r.detail,
      listening: r.listening,
      firewall: r.firewall,
      exposedPorts: r.exposedPorts,
      webSapi: r.webSapi,
      config: relevantConfig(src, h.inv),
      inKev: c.kev,
      cvss: c.cvss,
      needsConfirmation: !!c.textOnly || distroVerdict === "unknown",
    });
  }
  return out;
}

// ---------------------------------------------------------------- g. hard rules
export function expectedStatus(e: Evidence): { status: FindingStatus; uncertain: boolean } {
  const vulnerable = e.distroVerdict === "vulnerable" || (e.distroVerdict === "unknown" && e.naiveVerdict !== "not_vulnerable");
  if (!vulnerable) return { status: "not_affected", uncertain: e.distroVerdict === "unknown" };
  if (e.reachable === false) return { status: "vulnerable_not_exposed", uncertain: e.distroVerdict === "unknown" };
  return { status: "exposed", uncertain: e.reachable === null || e.distroVerdict === "unknown" };
}

export function priorityFor(status: FindingStatus, kev: boolean): Priority {
  if (status === "exposed") return kev ? "critical" : "high";
  if (status === "vulnerable_not_exposed") return "medium";
  return "info";
}

export function evidenceHash(e: Evidence): string {
  return sha256(JSON.stringify(e));
}

/** Deterministic fallback text when the LLM is unavailable. */
export function fallbackRationale(e: Evidence, status: FindingStatus): string {
  const lines = [
    `**${e.hostName}** has \`${e.sourcePackage}\` ${e.installedVersion} (upstream ${e.upstreamVersion}).`,
    `Naive version check: ${e.naiveVerdict}. Distro advisory verdict: ${e.distroVerdict} — ${e.installedVsFixed}.`,
    `Reachability: ${e.reachability}.`,
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
