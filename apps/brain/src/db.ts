import { Database } from "bun:sqlite";
import type {
  ActionRecord, AuditEvent, Finding, FindingStatus, HostSummary, InventorySnapshot, Report, Settings,
} from "@prohori/shared";
import { env } from "./env";

export const db = new Database(env.dbPath, { create: true });
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA busy_timeout = 5000;");

db.exec(`
CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  last_seen TEXT,
  os TEXT,
  daemon_version TEXT,
  tier2_enabled INTEGER NOT NULL DEFAULT 0,
  raw_match_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS inventories (
  host_id TEXT PRIMARY KEY,
  snapshot TEXT NOT NULL,
  hash TEXT NOT NULL,
  changed INTEGER NOT NULL DEFAULT 0,
  received_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  status TEXT NOT NULL,
  priority TEXT NOT NULL,
  evidence_hash TEXT NOT NULL DEFAULT '',
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(host_id, cve_id)
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  host_id TEXT,
  cve_id TEXT,
  data TEXT
);
CREATE INDEX IF NOT EXISTS audit_seq ON audit_log(seq);
CREATE INDEX IF NOT EXISTS audit_host ON audit_log(host_id);
CREATE TABLE IF NOT EXISTS osv_cache (id TEXT PRIMARY KEY, data TEXT, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kev_cache (key TEXT PRIMARY KEY, data TEXT NOT NULL, fetched_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS demo_hold (cve_id TEXT PRIMARY KEY, state TEXT NOT NULL);
`);

// migration: actor column on audit_log
if (!(db.query("PRAGMA table_info(audit_log)").all() as { name: string }[]).some((c) => c.name === "actor")) {
  db.exec("ALTER TABLE audit_log ADD COLUMN actor TEXT NOT NULL DEFAULT 'prohori'");
}

export const nowIso = () => new Date().toISOString();
export const newId = (prefix: string) => `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;

export function sha256(s: string): string {
  return new Bun.CryptoHasher("sha256").update(s).digest("hex");
}

// ---------------- settings ----------------
const DEFAULT_SETTINGS: Settings = {
  reportEmails: env.defaultReportEmails,
  scanIntervalSec: 45,
  wildRefreshSec: 900,
  tier2Enabled: true,
};

export function getSettings(): Settings {
  const rows = db.query("SELECT key, value FROM settings").all() as { key: string; value: string }[];
  const s: any = { ...DEFAULT_SETTINGS };
  for (const r of rows) if (r.key in DEFAULT_SETTINGS) s[r.key] = JSON.parse(r.value);
  return s as Settings;
}

export function saveSettings(patch: Partial<Settings>): Settings {
  const stmt = db.query("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
  for (const [k, v] of Object.entries(patch)) {
    if (k in DEFAULT_SETTINGS && v !== undefined) stmt.run(k, JSON.stringify(v));
  }
  return getSettings();
}

// ---------------- hosts ----------------
interface HostRow {
  id: string; name: string; token_hash: string; last_seen: string | null; os: string | null;
  daemon_version: string | null; tier2_enabled: number; raw_match_count: number; created_at: string;
}

export function upsertSeedHost(id: string, name: string, token: string) {
  db.query(
    `INSERT INTO hosts(id, name, token_hash, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET name = excluded.name, token_hash = excluded.token_hash`,
  ).run(id, name, sha256(token), nowIso());
}

export function createHost(id: string, name: string, token: string) {
  db.query("INSERT INTO hosts(id, name, token_hash, created_at) VALUES (?, ?, ?, ?)").run(id, name, sha256(token), nowIso());
}

export function getHostRow(id: string): HostRow | null {
  return (db.query("SELECT * FROM hosts WHERE id = ?").get(id) as HostRow | null) ?? null;
}

export function listHostRows(): HostRow[] {
  return db.query("SELECT * FROM hosts ORDER BY id").all() as HostRow[];
}

export function verifyHostToken(id: string, token: string): boolean {
  const row = getHostRow(id);
  if (!row) return false;
  const a = Buffer.from(row.token_hash);
  const b = Buffer.from(sha256(token));
  return a.length === b.length && timingSafe(a, b);
}
function timingSafe(a: Buffer, b: Buffer) {
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function updateHostMeta(id: string, patch: { lastSeen?: string; os?: string; daemonVersion?: string; tier2Enabled?: boolean; rawMatchCount?: number }) {
  if (patch.lastSeen !== undefined) db.query("UPDATE hosts SET last_seen = ? WHERE id = ?").run(patch.lastSeen, id);
  if (patch.os !== undefined) db.query("UPDATE hosts SET os = ? WHERE id = ?").run(patch.os, id);
  if (patch.daemonVersion !== undefined) db.query("UPDATE hosts SET daemon_version = ? WHERE id = ?").run(patch.daemonVersion, id);
  if (patch.tier2Enabled !== undefined) db.query("UPDATE hosts SET tier2_enabled = ? WHERE id = ?").run(patch.tier2Enabled ? 1 : 0, id);
  if (patch.rawMatchCount !== undefined) db.query("UPDATE hosts SET raw_match_count = ? WHERE id = ?").run(patch.rawMatchCount, id);
}

export const emptyCounts = (): Record<FindingStatus, number> => ({ exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 });

export function hostSummary(row: HostRow, online: boolean): HostSummary {
  const counts = emptyCounts();
  const rows = db.query("SELECT status, COUNT(*) n FROM findings WHERE host_id = ? GROUP BY status").all(row.id) as { status: FindingStatus; n: number }[];
  for (const r of rows) counts[r.status] = r.n;
  return {
    id: row.id,
    name: row.name,
    status: online ? "online" : "offline",
    lastSeen: row.last_seen,
    os: row.os,
    daemonVersion: row.daemon_version,
    tier2Enabled: !!row.tier2_enabled,
    findingCounts: counts,
    rawMatchCount: row.raw_match_count,
  };
}

// ---------------- inventory ----------------
export function inventoryHash(s: InventorySnapshot): string {
  const pk = [...(s.packages ?? [])].map((p) => `${p.name}=${p.version}`).sort().join("\n");
  const ports = [...(s.listeningPorts ?? [])].map((p) => `${p.protocol}:${p.address}:${p.port}:${p.process}`).sort().join("\n");
  const fw = [...(s.firewall?.closedPorts ?? [])].map((r) => `${r.port}/${r.protocol}`).sort().join(",");
  return sha256(pk + "\n--\n" + ports + "\n--\n" + fw);
}

/** Saves the snapshot; returns whether packages/ports differ from the previous snapshot (false for the first one). */
export function saveInventory(hostId: string, snap: InventorySnapshot): { changed: boolean; first: boolean } {
  const prev = db.query("SELECT hash FROM inventories WHERE host_id = ?").get(hostId) as { hash: string } | null;
  const hash = inventoryHash(snap);
  const changed = !!prev && prev.hash !== hash;
  db.query(
    `INSERT INTO inventories(host_id, snapshot, hash, changed, received_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(host_id) DO UPDATE SET snapshot = excluded.snapshot, hash = excluded.hash, changed = excluded.changed, received_at = excluded.received_at`,
  ).run(hostId, JSON.stringify(snap), hash, changed ? 1 : 0, nowIso());
  return { changed, first: !prev };
}

export function getInventory(hostId: string): InventorySnapshot | null {
  const r = db.query("SELECT snapshot FROM inventories WHERE host_id = ?").get(hostId) as { snapshot: string } | null;
  return r ? (JSON.parse(r.snapshot) as InventorySnapshot) : null;
}

// ---------------- findings ----------------
const PRIORITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
const STATUS_ORDER = { exposed: 0, vulnerable_not_exposed: 1, not_affected: 2 } as const;

export function sortFindings(fs: Finding[]): Finding[] {
  return fs.sort(
    (a, b) =>
      PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] ||
      STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
      a.hostId.localeCompare(b.hostId) ||
      a.cveId.localeCompare(b.cveId),
  );
}

export function listFindings(filter: { status?: string; hostId?: string; cveId?: string } = {}): Finding[] {
  const where: string[] = [];
  const args: string[] = [];
  if (filter.status) { where.push("status = ?"); args.push(filter.status); }
  if (filter.hostId) { where.push("host_id = ?"); args.push(filter.hostId); }
  if (filter.cveId) { where.push("cve_id = ?"); args.push(filter.cveId); }
  const sql = `SELECT data FROM findings ${where.length ? "WHERE " + where.join(" AND ") : ""}`;
  const rows = db.query(sql).all(...args) as { data: string }[];
  return sortFindings(rows.map((r) => JSON.parse(r.data)));
}

export function getFinding(id: string): Finding | null {
  const r = db.query("SELECT data FROM findings WHERE id = ?").get(id) as { data: string } | null;
  return r ? JSON.parse(r.data) : null;
}

export function getFindingByKey(hostId: string, cveId: string): { finding: Finding; evidenceHash: string } | null {
  const r = db.query("SELECT data, evidence_hash FROM findings WHERE host_id = ? AND cve_id = ?").get(hostId, cveId) as
    | { data: string; evidence_hash: string }
    | null;
  return r ? { finding: JSON.parse(r.data), evidenceHash: r.evidence_hash } : null;
}

export function saveFinding(f: Finding, evidenceHash?: string) {
  db.query(
    `INSERT INTO findings(id, host_id, cve_id, status, priority, evidence_hash, data, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET status = excluded.status, priority = excluded.priority,
       evidence_hash = CASE WHEN excluded.evidence_hash = '' THEN findings.evidence_hash ELSE excluded.evidence_hash END,
       data = excluded.data, updated_at = excluded.updated_at`,
  ).run(f.id, f.hostId, f.cveId, f.status, f.priority, evidenceHash ?? "", JSON.stringify(f), f.updatedAt);
}

export function deleteFindingsForCves(cveIds: string[]): string[] {
  const ids: string[] = [];
  for (const c of cveIds) {
    const rows = db.query("SELECT id FROM findings WHERE cve_id = ?").all(c) as { id: string }[];
    ids.push(...rows.map((r) => r.id));
    db.query("DELETE FROM findings WHERE cve_id = ?").run(c);
  }
  return ids;
}

export function findingTotals(): Record<FindingStatus, number> {
  const counts = emptyCounts();
  const rows = db.query("SELECT status, COUNT(*) n FROM findings GROUP BY status").all() as { status: FindingStatus; n: number }[];
  for (const r of rows) counts[r.status] = r.n;
  return counts;
}

// ---------------- reports ----------------
export function saveReport(r: Report) {
  db.query(
    "INSERT INTO reports(id, created_at, data) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
  ).run(r.id, r.createdAt, JSON.stringify(r));
}
export function listReports(): Report[] {
  return (db.query("SELECT data FROM reports ORDER BY created_at DESC").all() as { data: string }[]).map((r) => JSON.parse(r.data));
}
export function getReport(id: string): Report | null {
  const r = db.query("SELECT data FROM reports WHERE id = ?").get(id) as { data: string } | null;
  return r ? JSON.parse(r.data) : null;
}
export function deleteReport(id: string) {
  db.query("DELETE FROM reports WHERE id = ?").run(id);
}

// ---------------- actions ----------------
export function saveAction(a: ActionRecord) {
  db.query(
    `INSERT INTO actions(id, host_id, state, created_at, data) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET state = excluded.state, data = excluded.data`,
  ).run(a.id, a.hostId, a.state, a.createdAt, JSON.stringify(a));
}
export function listActions(filter: { state?: string; hostId?: string } = {}): ActionRecord[] {
  const where: string[] = [];
  const args: string[] = [];
  if (filter.state) { where.push("state = ?"); args.push(filter.state); }
  if (filter.hostId) { where.push("host_id = ?"); args.push(filter.hostId); }
  const sql = `SELECT data FROM actions ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY created_at DESC`;
  return (db.query(sql).all(...args) as { data: string }[]).map((r) => ({
    decidedBy: null, decisionNote: null, threadId: null, supersedes: null, supersededBy: null, rolledBackBy: null, ...JSON.parse(r.data),
  }));
}
export function getAction(id: string): ActionRecord | null {
  const r = db.query("SELECT data FROM actions WHERE id = ?").get(id) as { data: string } | null;
  if (!r) return null;
  const a = JSON.parse(r.data);
  // normalise records created before the accountability fields existed
  return { decidedBy: null, decisionNote: null, threadId: null, supersedes: null, supersededBy: null, rolledBackBy: null, ...a };
}
export function deleteAction(id: string) {
  db.query("DELETE FROM actions WHERE id = ?").run(id);
}

// ---------------- audit ----------------
let auditSeq = ((db.query("SELECT MAX(seq) m FROM audit_log").get() as { m: number | null }).m ?? 0);

/** actor: "prohori" (system/agent, default), "daemon:<hostId>", or an admin username from X-Prohori-Actor. */
export function audit(
  kind: AuditEvent["kind"], message: string,
  extra: { hostId?: string; cveId?: string; data?: Record<string, unknown>; actor?: string } = {},
): AuditEvent {
  const { actor = "prohori", ...rest } = extra;
  const ev: AuditEvent = { id: newId("ev"), at: nowIso(), kind, message, actor, ...rest };
  db.query("INSERT INTO audit_log(id, seq, at, kind, message, host_id, cve_id, data, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
    ev.id, ++auditSeq, ev.at, kind, message, extra.hostId ?? null, extra.cveId ?? null, extra.data ? JSON.stringify(extra.data) : null, actor,
  );
  console.log(`[audit] ${kind} (${actor}): ${message}`);
  return ev;
}

export function listAudit(limit = 100, filter: { hostId?: string; kind?: string } = {}): AuditEvent[] {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (filter.hostId) { where.push("host_id = ?"); args.push(filter.hostId); }
  if (filter.kind) {
    const kinds = filter.kind.split(",").filter(Boolean);
    where.push(`kind IN (${kinds.map(() => "?").join(",")})`);
    args.push(...kinds);
  }
  const rows = db.query(`SELECT * FROM audit_log ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY seq DESC LIMIT ?`).all(...args, limit) as any[];
  return rows.map((r) => {
    const ev: AuditEvent = { id: r.id, at: r.at, kind: r.kind, message: r.message, actor: r.actor ?? "prohori" };
    if (r.host_id) ev.hostId = r.host_id;
    if (r.cve_id) ev.cveId = r.cve_id;
    if (r.data) ev.data = JSON.parse(r.data);
    return ev;
  });
}

// ---------------- demo hold ----------------
export function initHold(ids: string[]) {
  const stmt = db.query("INSERT OR IGNORE INTO demo_hold(cve_id, state) VALUES (?, 'held')");
  for (const id of ids) stmt.run(id);
}
export function holdState(): { held: string[]; injected: string[] } {
  const rows = db.query("SELECT cve_id, state FROM demo_hold ORDER BY cve_id").all() as { cve_id: string; state: string }[];
  return {
    held: rows.filter((r) => r.state === "held").map((r) => r.cve_id),
    injected: rows.filter((r) => r.state === "injected").map((r) => r.cve_id),
  };
}
export function setHold(ids: string[], state: "held" | "injected") {
  const stmt = db.query("INSERT INTO demo_hold(cve_id, state) VALUES (?, ?) ON CONFLICT(cve_id) DO UPDATE SET state = excluded.state");
  for (const id of ids) stmt.run(id, state);
}
