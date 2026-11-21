// OSV.dev client with a SQLite cache for vuln details.
import { db, nowIso } from "../db";
import { canonicalCve, cvss3Score, type VersionRange } from "./versions";

const OSV = "https://api.osv.dev/v1";
const DETAIL_TTL_MS = 6 * 3600_000;

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  upstream?: string[];
  related?: string[];
  published?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  affected?: {
    package?: { name: string; ecosystem: string; purl?: string };
    ranges?: { type: string; repo?: string; events: Record<string, string>[]; database_specific?: any }[];
    versions?: string[];
    ecosystem_specific?: any;
    database_specific?: any;
  }[];
  database_specific?: any;
  references?: { type: string; url: string }[];
}

export interface PkgQuery { name: string; version: string; ecosystem: string }

async function fetchJson(url: string, init?: RequestInit, tries = 3): Promise<any> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      lastErr = e;
      await Bun.sleep(500 * (i + 1));
    }
  }
  throw lastErr;
}

/** querybatch → list of vuln ids per query (handles pagination). */
export async function queryBatch(queries: PkgQuery[]): Promise<string[][]> {
  const out: string[][] = queries.map(() => []);
  if (!queries.length) return out;
  const body = (qs: { q: PkgQuery; token?: string }[]) => ({
    queries: qs.map(({ q, token }) => ({
      version: q.version,
      package: { name: q.name, ecosystem: q.ecosystem },
      ...(token ? { page_token: token } : {}),
    })),
  });
  let pending = queries.map((q, idx) => ({ q, idx, token: undefined as string | undefined }));
  for (let round = 0; pending.length && round < 10; round++) {
    const res = await fetchJson(`${OSV}/querybatch`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body(pending)),
    });
    const next: typeof pending = [];
    (res?.results ?? []).forEach((r: any, i: number) => {
      const p = pending[i]!;
      for (const v of r.vulns ?? []) out[p.idx]!.push(v.id);
      if (r.next_page_token) next.push({ ...p, token: r.next_page_token });
    });
    pending = next;
  }
  return out;
}

/** GET /v1/vulns/{id} with cache. Returns null on 404. */
export async function getVuln(id: string): Promise<OsvVuln | null> {
  const row = db.query("SELECT data, fetched_at FROM osv_cache WHERE id = ?").get(id) as { data: string | null; fetched_at: string } | null;
  if (row && Date.now() - Date.parse(row.fetched_at) < DETAIL_TTL_MS) return row.data ? JSON.parse(row.data) : null;
  try {
    const v = await fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`);
    db.query("INSERT INTO osv_cache(id, data, fetched_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at")
      .run(id, v ? JSON.stringify(v) : null, nowIso());
    return v;
  } catch (e) {
    if (row) return row.data ? JSON.parse(row.data) : null; // stale cache beats nothing
    throw e;
  }
}

export async function getVulns(ids: string[], concurrency = 8): Promise<Map<string, OsvVuln | null>> {
  const out = new Map<string, OsvVuln | null>();
  const queue = [...new Set(ids)];
  await Promise.all(
    Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length) {
        const id = queue.shift()!;
        try { out.set(id, await getVuln(id)); } catch { out.set(id, null); }
      }
    }),
  );
  return out;
}

// ---------------- helpers on OSV records ----------------
export function cveOf(v: OsvVuln): string | null {
  return canonicalCve(v.id, v.aliases ?? [], v.upstream ?? []);
}

export function allIds(v: OsvVuln): string[] {
  return [v.id, ...(v.aliases ?? []), ...(v.upstream ?? [])].map((s) => s.toUpperCase());
}

/** Best severity info: numeric CVSS (v3 computed), the vector string, and a qualitative distro label. */
export function severityOf(v: OsvVuln | null): { score: number | null; vector: string | null; label: string | null } {
  if (!v) return { score: null, vector: null, label: null };
  let score: number | null = null;
  let vector: string | null = null;
  let label: string | null = null;
  for (const s of v.severity ?? []) {
    if (s.type === "CVSS_V3") {
      const sc = cvss3Score(s.score);
      if (sc !== null && (score === null || sc > score)) { score = sc; vector = s.score; }
    } else if (s.type === "CVSS_V4" && !vector) {
      vector = s.score;
    } else if (s.type === "Ubuntu" || s.type === "Debian") {
      label = s.score.toLowerCase();
    }
  }
  const ds = v.database_specific?.severity;
  if (!label && typeof ds === "string") label = ds.toLowerCase();
  return { score, vector, label };
}

/** Upstream ranges from a CVE record: CPE extracted_events, or SEMVER/ECOSYSTEM ranges without a distro ecosystem. */
export function upstreamRanges(v: OsvVuln | null): VersionRange[] {
  if (!v) return [];
  const out: VersionRange[] = [];
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const ex of r.database_specific?.extracted_events ?? []) {
        const range: VersionRange = {};
        for (const e of ex.range ?? []) {
          if (e.introduced) range.introduced = e.introduced;
          if (e.fixed) range.fixed = e.fixed;
          if (e.last_affected) range.lastAffected = e.last_affected;
        }
        if (range.fixed || range.lastAffected) out.push(range);
      }
      const eco = a.package?.ecosystem ?? "";
      if ((r.type === "SEMVER" || r.type === "ECOSYSTEM") && !/^(Ubuntu|Debian)/.test(eco)) {
        let cur: VersionRange = {};
        for (const e of r.events) {
          if (e.introduced !== undefined) { if (cur.introduced !== undefined) out.push(cur); cur = { introduced: e.introduced }; }
          if (e.fixed) { cur.fixed = e.fixed; out.push(cur); cur = {}; }
          if (e.last_affected) { cur.lastAffected = e.last_affected; out.push(cur); cur = {}; }
        }
        if (cur.introduced !== undefined) out.push(cur);
      }
    }
  }
  return out;
}

/** Distro fixed version for (ecosystem, source package) from an UBUNTU-/DEBIAN- record. */
export function distroFixed(v: OsvVuln | null, ecosystem: string, sourcePkg: string): { fixed: string | null; hasRecord: boolean } {
  if (!v) return { fixed: null, hasRecord: false };
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || a.package?.name !== sourcePkg) continue;
    for (const r of a.ranges ?? []) for (const e of r.events) if (e.fixed) return { fixed: e.fixed, hasRecord: true };
    return { fixed: null, hasRecord: true };
  }
  return { fixed: null, hasRecord: false };
}

/** OSV ecosystem for a host OS. */
export function ecosystemFor(os: { name?: string; platform?: string; versionId?: string; version?: string } | null | undefined): string | null {
  if (!os) return null;
  const plat = (os.platform || os.name || "").toLowerCase();
  const vid = os.versionId ?? "";
  if (plat.includes("ubuntu")) {
    const [maj, min] = vid.split(".").map(Number);
    const lts = (os.version ?? "").includes("LTS") || (maj! % 2 === 0 && min === 4);
    return lts ? `Ubuntu:${vid}:LTS` : `Ubuntu:${vid}`;
  }
  if (plat.includes("debian")) return `Debian:${vid.split(".")[0]}`;
  return null;
}
