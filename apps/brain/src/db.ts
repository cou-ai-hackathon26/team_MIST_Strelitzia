import { Database } from "bun:sqlite";
import type {
  ActionRecord, AuditEvent, Finding, FindingStatus, HostSummary, InventorySnapshot, Report, Settings, ThreatProfile,
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
  cveScanEnabled: false,
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
  daemon_version: string | null; raw_match_count: number; created_at: string;
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

export function updateHostMeta(id: string, patch: { lastSeen?: string; os?: string; daemonVersion?: string; rawMatchCount?: number }) {
  if (patch.lastSeen !== undefined) db.query("UPDATE hosts SET last_seen = ? WHERE id = ?").run(patch.lastSeen, id);
  if (patch.os !== undefined) db.query("UPDATE hosts SET os = ? WHERE id = ?").run(patch.os, id);
  if (patch.daemonVersion !== undefined) db.query("UPDATE hosts SET daemon_version = ? WHERE id = ?").run(patch.daemonVersion, id);
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
/** Full demo reset: drop all findings, reports, actions, chat threads and the audit log. Keeps OSV/KEV caches, triage decisions and threat profiles. */
export function wipeOperationalState() {
  for (const t of ["findings", "reports", "actions", "chat_threads", "audit_log"]) db.run(`DELETE FROM ${t}`);
}

export function deleteReport(id: string) {
  db.query("DELETE FROM reports WHERE id = ?").run(id);
}

// ---------------- chat threads (index for the "Ask Sentinel" thread list) ----------------
db.run(`CREATE TABLE IF NOT EXISTS chat_threads (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, started_by TEXT, created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, message_count INTEGER NOT NULL DEFAULT 0, action_id TEXT
)`);
export interface ChatThreadRow { id: string; title: string; started_by: string | null; created_at: string; updated_at: string; message_count: number; action_id: string | null }
export function touchChatThread(t: { id: string; title: string; actor: string; actionId: string | null }) {
  const now = nowIso();
  db.query(
    `INSERT INTO chat_threads(id, title, started_by, created_at, updated_at, message_count, action_id) VALUES (?, ?, ?, ?, ?, 1, ?)
     ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, message_count = chat_threads.message_count + 1,
       action_id = COALESCE(chat_threads.action_id, excluded.action_id)`,
  ).run(t.id, t.title, t.actor, now, now, t.actionId);
}
export function upsertChatThreadIfMissing(t: { id: string; title: string; createdAt: string; updatedAt: string; actionId: string | null }) {
  db.query(
    `INSERT OR IGNORE INTO chat_threads(id, title, started_by, created_at, updated_at, message_count, action_id) VALUES (?, ?, NULL, ?, ?, 0, ?)`,
  ).run(t.id, t.title, t.createdAt, t.updatedAt, t.actionId);
}
export function listChatThreads(limit = 50): ChatThreadRow[] {
  return db.query("SELECT * FROM chat_threads ORDER BY updated_at DESC LIMIT ?").all(limit) as ChatThreadRow[];
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
    decidedBy: null, decisionNote: null, threadId: null, supersedes: null, supersededBy: null, rolledBackBy: null, progress: null, ...JSON.parse(r.data),
  }));
}
export function getAction(id: string): ActionRecord | null {
  const r = db.query("SELECT data FROM actions WHERE id = ?").get(id) as { data: string } | null;
  if (!r) return null;
  const a = JSON.parse(r.data);
  // normalise records created before the accountability fields existed
  return { decidedBy: null, decisionNote: null, threadId: null, supersedes: null, supersededBy: null, rolledBackBy: null, progress: null, ...a };
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

// ---------------- Sentinel caches (per CVE): triage decisions and threat profiles ----------------
db.exec(`
CREATE TABLE IF NOT EXISTS triage (
  cve_id TEXT PRIMARY KEY,
  decision TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_profiles (
  cve_id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`);

export interface TriageRow { cveId: string; decision: "investigate" | "ignore"; decidedBy: "rule" | "sentinel"; reason: string; createdAt: string }

export function getTriage(cveId: string): TriageRow | null {
  const r = db.query("SELECT * FROM triage WHERE cve_id = ?").get(cveId) as any;
  return r ? { cveId: r.cve_id, decision: r.decision, decidedBy: r.decided_by, reason: r.reason, createdAt: r.created_at } : null;
}
export function saveTriage(t: Omit<TriageRow, "createdAt">) {
  db.query(
    `INSERT INTO triage(cve_id, decision, decided_by, reason, created_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(cve_id) DO UPDATE SET decision = excluded.decision, decided_by = excluded.decided_by, reason = excluded.reason, created_at = excluded.created_at`,
  ).run(t.cveId, t.decision, t.decidedBy, t.reason, nowIso());
}
export function listTriage(): TriageRow[] {
  return (db.query("SELECT * FROM triage ORDER BY cve_id").all() as any[]).map((r) => ({
    cveId: r.cve_id, decision: r.decision, decidedBy: r.decided_by, reason: r.reason, createdAt: r.created_at,
  }));
}

export function getProfile(cveId: string): ThreatProfile | null {
  const r = db.query("SELECT data FROM threat_profiles WHERE cve_id = ?").get(cveId.toUpperCase()) as { data: string } | null;
  return r ? JSON.parse(r.data) : null;
}
export function saveProfile(p: ThreatProfile) {
  db.query(
    "INSERT INTO threat_profiles(cve_id, data, created_at) VALUES (?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET data = excluded.data, created_at = excluded.created_at",
  ).run(p.cveId.toUpperCase(), JSON.stringify(p), p.generatedAt);
}
