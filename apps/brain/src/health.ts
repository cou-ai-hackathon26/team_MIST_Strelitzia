// Inventory trust ("can Sentinel assess this host right now?"). One pure-ish function decides; everything that
// could propose, approve or resolve something on a host asks it first. A host whose daemon is down, silent or
// has stopped delivering inventory is "unassessable": Sentinel proposes NOTHING for it (a fix derived from an
// old picture of the server could be wrong or unsafe) and the dashboard raises an alert for an admin.
import type { HostHealth } from "@prohori/shared";
import { audit, getHostRow, getInventoryReceivedAt, listHostRows } from "./db";
import { env } from "./env";
import { isOnline } from "./gateway";

const BOOT_AT = Date.now();
/** After a brain restart daemons need a moment to reconnect: block meanwhile, but don't raise the alarm yet. */
const STARTUP_GRACE_MS = 60_000;

const ago = (iso: string | null, now = Date.now()) => {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
};

export function computeHealth(hostId: string, now = Date.now()): HostHealth {
  const row = getHostRow(hostId);
  const lastInventoryAt = getInventoryReceivedAt(hostId);
  const inGrace = now - BOOT_AT < STARTUP_GRACE_MS;
  const ok: HostHealth = { state: "ok", alert: false, kind: null, reason: "", since: null, lastInventoryAt };
  if (!row) return { ...ok, state: "unassessable", kind: "never_reported", reason: "unknown host" };

  if (!isOnline(hostId)) {
    if (!row.last_seen && !lastInventoryAt) {
      return { state: "unassessable", alert: false, kind: "never_reported", reason: "the daemon has never connected", since: null, lastInventoryAt };
    }
    return {
      state: "unassessable", alert: !inGrace, kind: "offline",
      reason: `daemon not responding (last heartbeat ${ago(row.last_seen, now)})`, since: row.last_seen ?? lastInventoryAt, lastInventoryAt,
    };
  }
  if (!lastInventoryAt) {
    // connected, but the first inventory has not arrived yet (it is sent right after connecting)
    return { state: "unassessable", alert: false, kind: "never_reported", reason: "connected, waiting for the first inventory", since: null, lastInventoryAt };
  }
  const age = (now - Date.parse(lastInventoryAt)) / 1000;
  if (age > env.inventoryStaleSec) {
    return {
      state: "unassessable", alert: true, kind: "stale",
      reason: `daemon is connected but has not delivered an inventory for ${ago(lastInventoryAt, now).replace(" ago", "")} (limit ${Math.round(env.inventoryStaleSec)}s)`,
      since: lastInventoryAt, lastInventoryAt,
    };
  }
  return ok;
}

/** null = the host can be assessed; otherwise the reason it cannot. */
export function blockReason(hostId: string): string | null {
  const h = computeHealth(hostId);
  return h.state === "ok" ? null : h.reason;
}

export const hostLabel = (hostId: string) => getHostRow(hostId)?.name ?? hostId;

/** Hosts a scan must skip, with why. */
export function unassessableHosts(): { id: string; name: string; health: HostHealth }[] {
  return listHostRows()
    .map((r) => ({ id: r.id, name: r.name, health: computeHealth(r.id) }))
    .filter((h) => h.health.state !== "ok");
}

/**
 * Watchdog: audits every change of a host's trust state (so the event log shows when Sentinel stopped and resumed
 * proposing for a host) and calls `onRecovered` when a host that was blocked becomes assessable again.
 */
export function startHealthWatch(onRecovered: (hostId: string) => void) {
  const last = new Map<string, string>();
  const tick = () => {
    for (const r of listHostRows()) {
      const h = computeHealth(r.id);
      const key = `${h.state}|${h.alert}|${h.kind}`;
      const prev = last.get(r.id);
      if (prev === key) continue;
      last.set(r.id, key);
      if (h.state === "unassessable" && h.alert) {
        audit("host_unassessable", `${r.name} cannot be assessed: ${h.reason}. Sentinel will not propose fixes for it until it reports again.`, {
          hostId: r.id, data: { kind: h.kind, since: h.since, lastInventoryAt: h.lastInventoryAt },
        });
      } else if (h.state === "ok" && prev?.startsWith("unassessable|true")) {
        audit("host_recovered", `${r.name} is reporting again; Sentinel is assessing it again.`, { hostId: r.id });
        try { onRecovered(r.id); } catch (e) { console.error("[health] recovery hook failed", e); }
      }
    }
  };
  tick();
  return setInterval(tick, 5000);
}
