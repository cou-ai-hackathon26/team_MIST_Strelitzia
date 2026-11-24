// Version helpers: distro → upstream, upstream compare, dpkg compare, CVSS v3 base score.

/** "1:8.3.6-0ubuntu0.24.04.13" → "8.3.6"; "5.5.9+dfsg-1ubuntu4" → "5.5.9". */
export function upstreamVersion(distroVersion: string): string {
  let v = distroVersion.trim();
  const colon = v.indexOf(":");
  if (colon >= 0 && /^\d+$/.test(v.slice(0, colon))) v = v.slice(colon + 1);
  const dash = v.lastIndexOf("-");
  if (dash > 0) v = v.slice(0, dash);
  v = v.split(/[+~]/)[0]!;
  return v;
}

/** Compare dotted upstream versions numerically (non-numeric suffixes compared lexically). */
export function compareUpstream(a: string, b: string): number {
  const pa = a.split(/[.\-]/);
  const pb = b.split(/[.\-]/);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = parseInt(x, 10);
    const ny = parseInt(y, 10);
    if (!isNaN(nx) && !isNaN(ny) && nx !== ny) return nx - ny;
    const rx = x.replace(/^\d+/, "");
    const ry = y.replace(/^\d+/, "");
    if (rx !== ry) return rx < ry ? -1 : 1;
  }
  return 0;
}

export interface VersionRange { introduced?: string; fixed?: string; lastAffected?: string }

/** True if version falls in any range (introduced inclusive, fixed exclusive, last_affected inclusive). */
export function inAnyRange(version: string, ranges: VersionRange[]): boolean {
  return ranges.some((r) => {
    if (r.introduced && r.introduced !== "0" && compareUpstream(version, r.introduced) < 0) return false;
    if (r.fixed && compareUpstream(version, r.fixed) >= 0) return false;
    if (r.lastAffected && compareUpstream(version, r.lastAffected) > 0) return false;
    return true;
  });
}

// ---- dpkg version comparison (Debian policy 5.6.12) ----
function order(c: string): number {
  if (c === "~") return -1;
  if (/\d/.test(c)) return 0;
  if (!c) return 0;
  if (/[A-Za-z]/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}
function verrevcmp(a: string, b: string): number {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !/\d/.test(a[i]!)) || (j < b.length && !/\d/.test(b[j]!))) {
      const ac = order(a[i] ?? "");
      const bc = order(b[j] ?? "");
      if (ac !== bc) return ac - bc;
      i++; j++;
    }
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    while (i < a.length && /\d/.test(a[i]!) && j < b.length && /\d/.test(b[j]!)) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i++; j++;
    }
    if (i < a.length && /\d/.test(a[i]!)) return 1;
    if (j < b.length && /\d/.test(b[j]!)) return -1;
    if (firstDiff) return firstDiff;
  }
  return 0;
}
function splitDeb(v: string) {
  let epoch = 0, rest = v;
  const c = v.indexOf(":");
  if (c >= 0) { epoch = parseInt(v.slice(0, c), 10) || 0; rest = v.slice(c + 1); }
  const d = rest.lastIndexOf("-");
  return d >= 0 ? { epoch, up: rest.slice(0, d), rev: rest.slice(d + 1) } : { epoch, up: rest, rev: "" };
}
export function compareDebian(a: string, b: string): number {
  const x = splitDeb(a), y = splitDeb(b);
  if (x.epoch !== y.epoch) return x.epoch - y.epoch;
  return verrevcmp(x.up, y.up) || verrevcmp(x.rev, y.rev);
}

// ---- CVSS v3.x base score ----
export function cvss3Score(vector: string): number | null {
  if (!vector.startsWith("CVSS:3")) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV as "N"];
  const AC = { L: 0.77, H: 0.44 }[m.AC as "L"];
  const UI = { N: 0.85, R: 0.62 }[m.UI as "N"];
  const changed = m.S === "C";
  const PR = changed ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR as "N"] : { N: 0.85, L: 0.62, H: 0.27 }[m.PR as "N"];
  const cia = (x?: string) => ({ H: 0.56, L: 0.22, N: 0 }[x as "H"]);
  const C = cia(m.C), I = cia(m.I), A = cia(m.A);
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - C!) * (1 - I!) * (1 - A!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * AV! * AC! * PR! * UI!;
  if (impact <= 0) return 0;
  const roundUp = (x: number) => Math.ceil(x * 10 - 1e-9) / 10;
  return changed ? roundUp(Math.min(1.08 * (impact + expl), 10)) : roundUp(Math.min(impact + expl, 10));
}

/** Canonical CVE id for an OSV id + aliases/upstream; null if none. */
export function canonicalCve(id: string, aliases: string[] = [], upstream: string[] = []): string | null {
  const up = id.toUpperCase();
  if (/^CVE-\d{4}-\d+$/.test(up)) return up;
  for (const a of [...upstream, ...aliases]) if (/^CVE-\d{4}-\d+$/i.test(a)) return a.toUpperCase();
  const m = up.match(/^(?:UBUNTU|DEBIAN)-(CVE-\d{4}-\d+)$/);
  return m ? m[1]! : null;
}
