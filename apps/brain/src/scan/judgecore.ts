// Pure helpers of the "Judge an advisory" mode (no db/env imports, so they are unit-testable in isolation):
// matching the advisory's product to an installed source package, the per-host fix-status rule, and page scraping.
import { compareDebian, inAnyRange, upstreamVersion, type VersionRange } from "../vuln/versions";
import type { FindingStatus } from "@prohori/shared";

/** Deterministic one-paragraph verdict for chat and cards. */
export function judgmentSummary(input: {
  title: string; cveId: string | null; hostsTotal: number;
  hosts: { status: FindingStatus; naiveVerdict: string; fixStatus: { source: string; fixedVersion: string | null; detail: string } }[];
  fixAvailable: "yes" | "no" | "unknown";
}): string {
  const { hosts } = input;
  const n = (s: FindingStatus) => hosts.filter((h) => h.status === s).length;
  const vulnerable = n("exposed") + n("vulnerable_not_exposed");
  const naive = hosts.filter((h) => h.naiveVerdict === "vulnerable").length;
  const name = `${input.title}${input.cveId ? ` (${input.cveId})` : ""}`;
  if (!hosts.length) return `${name}: the affected package is not installed on any of the ${input.hostsTotal} host(s); nothing to do.`;
  const parts = [
    `${name}: the vulnerable build is installed on ${vulnerable} of ${input.hostsTotal} host(s); ${n("exposed")} exposed, ${n("vulnerable_not_exposed")} vulnerable but unreachable, ${n("not_affected")} not affected${hosts.length < input.hostsTotal ? ` (${input.hostsTotal - hosts.length} without the package)` : ""}.`,
    `A version-only check flags ${naive}.`,
  ];
  const distro = hosts.filter((h) => h.fixStatus.source === "distro_record");
  const anyFixed = distro.some((h) => h.fixStatus.fixedVersion);
  if (distro.length && !anyFixed) parts.push(`No fixed build is available (${distro[0]!.fixStatus.detail.split(":")[0]}).`);
  else if (anyFixed) parts.push(`A fixed distribution build exists (${distro.find((h) => h.fixStatus.fixedVersion)!.fixStatus.fixedVersion}).`);
  if (distro.length < hosts.length) {
    parts.push(`Fix status on ${hosts.length - distro.length} host(s) is advisory-only (upstream version numbers; distro backports not confirmed) — needs confirmation.`);
    if (input.fixAvailable === "no") parts.push("The advisory says no fix has been released.");
  }
  return parts.join(" ");
}

export const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

/** Minimal shape of an OSV distro record's affected entries (see vuln/osv.ts OsvVuln). */
export interface AffectedLike {
  package?: { name: string; ecosystem: string };
  ranges?: { events: Record<string, string>[] }[];
}

export interface SourceLike { version: string; binaries: { name: string }[] }

/** lowercase, alphanumerics only, no leading "lib", no trailing digits: "cyrus-sasl2" → "cyrussasl", "libsasl2-2" → "sasl" */
export function normPkg(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "").replace(/^lib/, "").replace(/\d+$/, "");
}

/**
 * Find the installed source package the advisory's product refers to. Order: (a) exact source package,
 * (b) exact binary package → its source, (c) normalised equality with a source package. No prefix matching
 * ("php" must not match "php-defaults").
 */
export function matchSourcePackage(
  sources: Map<string, SourceLike>, guess: string, aliases: string[] = [],
): { source: string; reason: string } | null {
  const names = [...new Set([guess, ...aliases].map((s) => s.trim().toLowerCase()).filter(Boolean))];
  for (const n of names) if (sources.has(n)) return { source: n, reason: `exact source package "${n}"` };
  for (const n of names) {
    for (const [src, s] of sources) {
      if (s.binaries.some((b) => b.name.toLowerCase() === n)) return { source: src, reason: `binary package "${n}" from source package "${src}"` };
    }
  }
  for (const n of names) {
    const k = normPkg(n);
    if (k.length < 3) continue;
    for (const src of sources.keys()) {
      if (normPkg(src) === k) return { source: src, reason: `normalised name "${n}" ≈ source package "${src}"` };
    }
  }
  return null;
}

export interface FixStatus {
  source: "distro_record" | "advisory_only";
  verdict: "vulnerable" | "not_vulnerable" | "unknown";
  fixedVersion: string | null;
  detail: string;
  /** the distro's fixed build (only for distro_record) — this is what Evidence.distroFixed carries */
  distroFixed: string | null;
}

/**
 * Whether the installed build is patched. A distro record entry for (ecosystem, source) decides; without one we
 * fall back to the advisory's upstream ranges. Unlike a scan, "record exists but OSV didn't match" is NOT evidence
 * of a fix here (nothing was matched), so a record without a fixed version means "no fixed build released".
 */
export function fixStatusFor(input: {
  installed: string; ecosystem: string | null; source: string;
  record: { id: string; affected?: AffectedLike[] } | null; recordLabel: string;
  ranges: VersionRange[]; upstreamFixed: string[];
}): FixStatus {
  const { installed, ecosystem, source, record, recordLabel, ranges } = input;
  const entry = ecosystem ? (record?.affected ?? []).find((a) => a.package?.ecosystem === ecosystem && a.package?.name === source) : undefined;
  if (record && entry) {
    const fixed = (entry.ranges ?? []).flatMap((r) => r.events).find((e) => e.fixed)?.fixed ?? null;
    if (fixed) {
      const d = compareDebian(installed, fixed);
      return {
        source: "distro_record", verdict: d < 0 ? "vulnerable" : "not_vulnerable", fixedVersion: fixed, distroFixed: fixed,
        detail: `${recordLabel} record ${record.id}: fixed in ${fixed} for ${ecosystem}; installed ${installed} ${d < 0 ? "< fixed (older than the patched build)" : ">= fixed (patched build)"}`,
      };
    }
    return {
      source: "distro_record", verdict: "vulnerable", fixedVersion: null, distroFixed: null,
      detail: `${recordLabel} record ${record.id}: no fixed build released for ${ecosystem}; installed ${installed} is affected`,
    };
  }
  const up = upstreamVersion(installed);
  const upFixed = input.upstreamFixed[0] ?? ranges.find((r) => r.fixed)?.fixed ?? null;
  const why = record ? `${recordLabel} record ${record.id} has no entry for ${source} on ${ecosystem ?? "this OS"}` : "no distribution record";
  if (!ranges.length) {
    return { source: "advisory_only", verdict: "unknown", fixedVersion: upFixed, distroFixed: null, detail: `${why}; the advisory states no version range — build status unknown` };
  }
  const hit = inAnyRange(up, ranges);
  return {
    source: "advisory_only", verdict: hit ? "vulnerable" : "not_vulnerable", fixedVersion: upFixed, distroFixed: null,
    detail: `${why}; upstream ${up} is ${hit ? "inside" : "outside"} the advisory's affected range ${fmtRanges(ranges)} (version numbers only — distro backports not confirmed)`,
  };
}

/** What a version-number-only check says (the contrast shown on the judgment page). */
export function naiveVerdictFor(installed: string, ranges: VersionRange[]): "vulnerable" | "not_vulnerable" | "unknown" {
  if (!ranges.length) return "unknown";
  return inAnyRange(upstreamVersion(installed), ranges) ? "vulnerable" : "not_vulnerable";
}

export function fmtRanges(ranges: VersionRange[]): string {
  return ranges.map((r) => [r.introduced && r.introduced !== "0" ? `>= ${r.introduced}` : "", r.fixed ? `< ${r.fixed}` : "", r.lastAffected ? `<= ${r.lastAffected}` : ""].filter(Boolean).join(" ") || "all versions").join("; ");
}

// ---------------------------------------------------------------- page scraping
/** Every CVE-/GHSA- id on the page (upper-cased, deduped, in order of appearance). */
export function idsOnPage(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,}\b|\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b/gi)) out.add(m[0].toUpperCase());
  return [...out].map((x) => (x.startsWith("GHSA") ? "GHSA" + x.slice(4).toLowerCase() : x));
}

/** Readable text of an HTML page (main/article if present). Entities decoded; scripts, styles and chrome dropped. */
export function htmlToText(html: string): string {
  let t = html;
  const main = t.match(/<main[\s\S]*?<\/main>/i)?.[0] ?? t.match(/<article[\s\S]*?<\/article>/i)?.[0];
  if (main) t = main;
  return t
    .replace(/<(script|style|noscript|svg|nav|header|footer|form|template)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<br\s*\/?>|<\/(p|div|li|h\d|tr|pre|table|section)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => safeChar(parseInt(h, 16)))
    .replace(/&#(\d{1,7});/g, (_, d) => safeChar(Number(d)))
    .replace(/&nbsp;/g, " ").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&")
    .replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}
const safeChar = (n: number) => (n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : " ");

const JUNK_LINK = /(^|\.)(githubassets\.com|githubusercontent\.com|gravatar\.com|schema\.org|googletagmanager\.com|google-analytics\.com|fonts\.googleapis\.com|fonts\.gstatic\.com|api\.githubcopilot\.com)$/i;

/** https links of the page (reference URLs written as text first, then hrefs; off-site before on-site), minus assets; capped. */
export function linksOnPage(html: string, pageUrl: string, max = 30): string[] {
  const scope = html.match(/<main[\s\S]*?<\/main>/i)?.[0] ?? html.match(/<article[\s\S]*?<\/article>/i)?.[0] ?? html;
  const raw: string[] = [];
  for (const m of htmlToText(scope).matchAll(/https:\/\/[^\s"'<>()\[\]\\]+/g)) raw.push(m[0].replace(/[.,;:]+$/, ""));
  for (const m of scope.matchAll(/href\s*=\s*["']([^"'#][^"']*)["']/gi)) raw.push(m[1]!.replace(/&amp;/g, "&"));
  const seen = new Set<string>([pageUrl]);
  const out: string[] = [];
  for (const r of raw) {
    let u: URL;
    try { u = new URL(r, pageUrl); } catch { continue; }
    if (u.protocol !== "https:" || JUNK_LINK.test(u.hostname)) continue;
    if (/\.(css|js|mjs|json|png|jpe?g|gif|svg|ico|woff2?|ttf|webp|webmanifest|mp4|zip|gz)$/i.test(u.pathname)) continue;
    const s = u.toString();
    u.hash = "";
    if (seen.has(s) || u.toString() === pageUrl) continue; // anchors on the page itself
    seen.add(s);
    out.push(s);
  }
  const host = new URL(pageUrl).hostname;
  return [...out.filter((u) => new URL(u).hostname !== host), ...out.filter((u) => new URL(u).hostname === host)].slice(0, max);
}
