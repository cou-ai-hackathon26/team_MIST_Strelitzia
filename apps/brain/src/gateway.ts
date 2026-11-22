// WebSocket gateway for prohori-daemons (protocol.ts).
import type { ServerWebSocket } from "bun";
import {
  DaemonToBrain, PROTOCOL_VERSION, TIMING, type BrainToDaemon, type InventorySnapshot, type QueryName,
} from "@prohori/shared";
import { audit, getHostRow, nowIso, saveInventory, updateHostMeta, verifyHostToken } from "./db";

export interface WsData { hostId: string | null; connectedAt: number }
type WS = ServerWebSocket<WsData>;

const conns = new Map<string, WS>();
const lastBeat = new Map<string, number>();
const online = new Set<string>();
const pendingQueries = new Map<string, { resolve: (rows: Record<string, unknown>[]) => void; reject: (e: Error) => void; timer: Timer }>();

export const gatewayHooks = {
  onActionResult: async (_m: { actionId: string; kind: "apply" | "rollback"; ok: boolean; diff: string; output: string }) => {},
  onInventory: (_hostId: string, _changed: boolean) => {},
};

export const isOnline = (hostId: string) => online.has(hostId);

function send(ws: WS, msg: BrainToDaemon) {
  ws.send(JSON.stringify(msg));
}

function markOnline(hostId: string) {
  lastBeat.set(hostId, Date.now());
  updateHostMeta(hostId, { lastSeen: nowIso() });
  if (!online.has(hostId)) {
    online.add(hostId);
    audit("host_online", `${getHostRow(hostId)?.name ?? hostId} came online`, { hostId });
  }
}

function markOffline(hostId: string, why: string) {
  if (online.delete(hostId)) audit("host_offline", `${getHostRow(hostId)?.name ?? hostId} went offline (${why})`, { hostId });
}

setInterval(() => {
  const cutoff = Date.now() - TIMING.offlineAfterSec * 1000;
  for (const id of [...online]) {
    if ((lastBeat.get(id) ?? 0) < cutoff) {
      markOffline(id, `no heartbeat for ${TIMING.offlineAfterSec}s`);
      try { conns.get(id)?.close(4000, "heartbeat timeout"); } catch {}
      conns.delete(id);
    }
  }
}, 5000);

export const websocketHandler = {
  open(_ws: WS) {},
  message(ws: WS, raw: string | Buffer) {
    let parsed: DaemonToBrain;
    try {
      const r = DaemonToBrain.safeParse(JSON.parse(String(raw)));
      if (!r.success) throw new Error(r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      parsed = r.data;
    } catch (e) {
      if (!ws.data.hostId) {
        send(ws, { id: crypto.randomUUID(), type: "reject", reason: `invalid message: ${(e as Error).message}` });
        ws.close(4001, "invalid");
      } else {
        console.warn(`[ws] ${ws.data.hostId}: dropped invalid message: ${(e as Error).message}`);
      }
      return;
    }

    if (!ws.data.hostId) {
      if (parsed.type !== "hello") {
        send(ws, { id: crypto.randomUUID(), type: "reject", reason: "first message must be hello" });
        ws.close(4001, "no hello");
        return;
      }
      if (parsed.protocolVersion !== PROTOCOL_VERSION || !verifyHostToken(parsed.hostId, parsed.token)) {
        send(ws, { id: crypto.randomUUID(), type: "reject", reason: "unknown host or bad token" });
        ws.close(4003, "auth");
        return;
      }
      const prev = conns.get(parsed.hostId);
      if (prev && prev !== ws) { try { prev.close(4002, "replaced by new connection"); } catch {} }
      ws.data.hostId = parsed.hostId;
      conns.set(parsed.hostId, ws);
      updateHostMeta(parsed.hostId, { daemonVersion: parsed.daemonVersion });
      send(ws, { id: crypto.randomUUID(), type: "welcome", heartbeatSec: TIMING.heartbeatSec, inventorySec: TIMING.inventorySec });
      markOnline(parsed.hostId);
      return;
    }

    const hostId = ws.data.hostId;
    switch (parsed.type) {
      case "hello":
        return; // already authenticated
      case "heartbeat":
        markOnline(hostId);
        return;
      case "inventory": {
        markOnline(hostId);
        const snap = parsed.snapshot as unknown as InventorySnapshot;
        if (!Array.isArray(snap.packages) || !snap.os) {
          console.warn(`[ws] ${hostId}: inventory missing packages/os`);
          return;
        }
        snap.listeningPorts ??= [];
        snap.processes ??= [];
        snap.config ??= {};
        snap.firewall ??= { available: false, closedPorts: [] };
        snap.firewall.closedPorts ??= [];
        const os = snap.os;
        updateHostMeta(hostId, { os: os.version ? `${os.name} ${os.version}` : os.name });
        const { changed } = saveInventory(hostId, snap);
        if (changed) audit("inventory_changed", `${getHostRow(hostId)?.name ?? hostId}: configuration change detected (packages, listeners or firewall)`, { hostId });
        gatewayHooks.onInventory(hostId, changed);
        return;
      }
      case "query_result": {
        const p = pendingQueries.get(parsed.requestId);
        if (!p) return;
        pendingQueries.delete(parsed.requestId);
        clearTimeout(p.timer);
        if (parsed.ok) p.resolve(parsed.rows ?? []);
        else p.reject(new Error(parsed.error ?? "query failed"));
        return;
      }
      case "action_result":
        markOnline(hostId);
        gatewayHooks.onActionResult(parsed).catch((e) => audit("error", `action_result handling failed: ${(e as Error).message}`, { hostId }));
        return;
    }
  },
  close(ws: WS) {
    const id = ws.data.hostId;
    if (id && conns.get(id) === ws) {
      conns.delete(id);
      markOffline(id, "disconnected");
    }
  },
};

function connOrThrow(hostId: string): WS {
  const ws = conns.get(hostId);
  if (!ws || !online.has(hostId)) throw new Error(`host ${hostId} is offline`);
  return ws;
}

export function queryHost(hostId: string, name: QueryName, params?: Record<string, string>): Promise<Record<string, unknown>[]> {
  const ws = connOrThrow(hostId);
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingQueries.delete(requestId);
      reject(new Error(`query ${name} on ${hostId} timed out after ${TIMING.queryTimeoutMs}ms`));
    }, TIMING.queryTimeoutMs);
    pendingQueries.set(requestId, { resolve, reject, timer });
    send(ws, { id: crypto.randomUUID(), type: "query", requestId, name, ...(params && Object.keys(params).length ? { params } : {}) });
  });
}

export function sendAction(hostId: string, actionId: string, actionType: string, params: Record<string, unknown>) {
  send(connOrThrow(hostId), { id: crypto.randomUUID(), type: "action", actionId, actionType, params });
}

export function sendRollback(hostId: string, actionId: string) {
  send(connOrThrow(hostId), { id: crypto.randomUUID(), type: "rollback", actionId });
}

export function requestRefresh(hostId?: string) {
  for (const [id, ws] of conns) {
    if (hostId && id !== hostId) continue;
    try { send(ws, { id: crypto.randomUUID(), type: "refresh" }); } catch {}
  }
}
