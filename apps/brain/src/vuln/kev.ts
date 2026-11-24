// CISA KEV catalog client (cached in SQLite, refreshed on a schedule).
import { audit, db, nowIso } from "../db";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction?: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

let entries: KevEntry[] = [];
let byId = new Map<string, KevEntry>();
let fetchedAt: string | null = null;

function load(list: KevEntry[], at: string) {
  entries = list;
  byId = new Map(list.map((e) => [e.cveID.toUpperCase(), e]));
  fetchedAt = at;
}

// warm from cache at import
{
  const row = db.query("SELECT data, fetched_at FROM kev_cache WHERE key = 'catalog'").get() as { data: string; fetched_at: string } | null;
  if (row) load(JSON.parse(row.data), row.fetched_at);
}

export async function refreshKev(reason = "scheduled"): Promise<number> {
  try {
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(60_000), headers: { "User-Agent": "prohori/0.1" } });
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const json = (await res.json()) as { vulnerabilities: KevEntry[] };
    const list = json.vulnerabilities.map((v) => ({
      cveID: v.cveID, vendorProject: v.vendorProject, product: v.product, vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded, shortDescription: v.shortDescription, requiredAction: v.requiredAction, dueDate: v.dueDate,
      knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
    }));
    const at = nowIso();
    db.query("INSERT INTO kev_cache(key, data, fetched_at) VALUES ('catalog', ?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at")
      .run(JSON.stringify(list), at);
    load(list, at);
    audit("wild_refreshed", `CISA KEV refreshed (${list.length} entries, ${reason})`, { data: { count: list.length } });
    return list.length;
  } catch (e) {
    audit("error", `KEV refresh failed: ${(e as Error).message}`);
    return entries.length;
  }
}

/** Ensure we have a catalog (fetch if never loaded). */
export async function ensureKev() {
  if (!entries.length) await refreshKev("initial");
}

export function kevEntry(cveId: string): KevEntry | null {
  return byId.get(cveId.toUpperCase()) ?? null;
}
export const inKev = (cveId: string) => byId.has(cveId.toUpperCase());

export function kevRecent(n = 30): KevEntry[] {
  return [...entries].sort((a, b) => b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID)).slice(0, n);
}
export const kevFetchedAt = () => fetchedAt;
