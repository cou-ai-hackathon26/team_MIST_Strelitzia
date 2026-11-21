// Dev-only stand-in for the brain, to exercise prohori-daemon end to end.
//   MOCK_BRAIN_PORT=4000 bun infra/dev/mock-brain.ts
// Scenario per host after its first inventory: query(packages) -> refresh -> (web-a, web-b) actions
// firewall_port 80/tcp closed + nginx_block_multipart -> both rolled back after ROLLBACK_AFTER_SEC.
// web-b has tier2 off, so it must refuse.
// Extra commands: POST /send/<hostId> with a brain->daemon message body (id is filled in; add ?raw to skip
// validation, to check that the daemon ignores invalid messages), e.g.
//   curl -XPOST localhost:4000/send/web-a -d '{"type":"action","actionId":"up1","actionType":"upgrade_packages","params":{"packages":["php8.3-fpm"]}}'
import { BrainToDaemon, DaemonToBrain } from "../../packages/shared/src/index.ts";
import type { ServerWebSocket } from "bun";

const PORT = Number(process.env.MOCK_BRAIN_PORT ?? 4000);
const ROLLBACK_AFTER_SEC = Number(process.env.ROLLBACK_AFTER_SEC ?? 30);
const TOKENS: Record<string, string> = { "web-a": "dev-token-a", "web-b": "dev-token-b", "batch-c": "dev-token-c" };

type Data = { hostId?: string; scenarioDone?: boolean };
const sockets = new Map<string, ServerWebSocket<Data>>();
const log = (...a: unknown[]) => console.log(new Date().toISOString(), ...a);

function send(ws: ServerWebSocket<Data>, msg: Record<string, unknown>, raw = false) {
  const full = { id: crypto.randomUUID(), ...msg };
  const ok = BrainToDaemon.safeParse(full);
  if (!ok.success && !raw) throw new Error(`mock built invalid message: ${ok.error.message}`);
  ws.send(JSON.stringify(full));
  log(`-> ${ws.data.hostId} ${msg.type}${msg.name ? ` ${msg.name}` : ""}${msg.actionType ? ` ${msg.actionType}` : ""}${msg.actionId ? ` ${msg.actionId}` : ""}`);
}

function scenario(ws: ServerWebSocket<Data>) {
  const host = ws.data.hostId!;
  send(ws, { type: "query", requestId: `q-${host}-packages`, name: "packages" });
  setTimeout(() => send(ws, { type: "refresh" }), 2000);
  if (host === "web-a" || host === "web-b") {
    const fwId = `act-${host}-fw80-${Date.now()}`;
    const blockId = `act-${host}-block-${Date.now()}`;
    setTimeout(() => send(ws, { type: "action", actionId: fwId, actionType: "firewall_port", params: { port: 80, protocol: "tcp", state: "closed" } }), 4000);
    setTimeout(() => send(ws, { type: "action", actionId: blockId, actionType: "nginx_block_multipart", params: {} }), 5000);
    setTimeout(() => send(ws, { type: "rollback", actionId: fwId }), 4000 + ROLLBACK_AFTER_SEC * 1000);
    setTimeout(() => send(ws, { type: "rollback", actionId: blockId }), 5000 + ROLLBACK_AFTER_SEC * 1000);
  }
}

Bun.serve<Data>({
  port: PORT,
  hostname: "0.0.0.0",
  async fetch(req, server) {
    const url = new URL(req.url);
    if (url.pathname === "/agent") {
      if (server.upgrade(req, { data: {} as Data })) return;
      return new Response("expected websocket", { status: 400 });
    }
    const m = /^\/send\/([\w-]+)$/.exec(url.pathname);
    if (m && req.method === "POST") {
      const ws = sockets.get(m[1]!);
      if (!ws) return new Response("host not connected\n", { status: 404 });
      try {
        send(ws, (await req.json()) as Record<string, unknown>, url.searchParams.has("raw"));
      } catch (e) {
        return new Response(`${(e as Error).message}\n`, { status: 400 });
      }
      return new Response("sent\n");
    }
    if (url.pathname === "/hosts") return Response.json([...sockets.keys()]);
    return new Response("mock brain\n");
  },
  websocket: {
    message(ws, raw) {
      let json: unknown;
      try {
        json = JSON.parse(String(raw));
      } catch {
        return log("!! non-JSON from daemon");
      }
      const p = DaemonToBrain.safeParse(json);
      if (!p.success) return log("!! INVALID daemon message:", p.error.message, String(raw).slice(0, 300));
      const msg = p.data;
      if (!ws.data.hostId && msg.type !== "hello") return log("!! first message was not hello");
      switch (msg.type) {
        case "hello":
          if (TOKENS[msg.hostId] !== msg.token) {
            ws.send(JSON.stringify({ id: crypto.randomUUID(), type: "reject", reason: "bad host id or token" }));
            ws.close();
            return log(`<- hello REJECTED ${msg.hostId}`);
          }
          ws.data.hostId = msg.hostId;
          sockets.set(msg.hostId, ws);
          log(`<- hello ${msg.hostId} daemon=${msg.daemonVersion} proto=${msg.protocolVersion} tier2=${msg.tier2Enabled}`);
          send(ws, { type: "welcome", heartbeatSec: 10, inventorySec: 120 });
          break;
        case "heartbeat":
          log(`<- heartbeat ${ws.data.hostId} ${msg.at}`);
          break;
        case "inventory": {
          const s = msg.snapshot as any;
          const php = (s.packages ?? []).filter((p: any) => p.source === "php8.3").map((p: any) => `${p.name}=${p.version}`);
          const ports = (s.listeningPorts ?? []).map((l: any) => `${l.protocol}/${l.address}:${l.port}(${l.process})`);
          log(
            `<- inventory ${ws.data.hostId} reason=${msg.reason} host=${s.hostname} os=${s.os?.name} ${s.os?.versionId} ${s.os?.codename} pkgs=${s.packages?.length} procs=${s.processes?.length}\n` +
              `     php8.3 (source=php8.3): ${php.join(", ") || "none"}\n     listening: ${ports.join(", ") || "none"}\n     firewall: ${JSON.stringify(s.firewall)}\n     config: ${JSON.stringify(s.config)}`,
          );
          if (!ws.data.scenarioDone) {
            ws.data.scenarioDone = true;
            scenario(ws);
          }
          break;
        }
        case "query_result":
          log(`<- query_result ${ws.data.hostId} ${msg.requestId} ok=${msg.ok} rows=${msg.rows?.length ?? 0} ${msg.error ?? ""} sample=${JSON.stringify(msg.rows?.find((r: any) => String(r.name).startsWith("php8.3")) ?? msg.rows?.[0] ?? null)}`);
          break;
        case "action_result":
          log(`<- action_result ${ws.data.hostId} ${msg.actionId} kind=${msg.kind} ok=${msg.ok}\n--- diff ---\n${msg.diff}\n--- output (${msg.output.length} chars) ---\n${msg.output}\n------------`);
          break;
      }
    },
    close(ws) {
      if (ws.data.hostId && sockets.get(ws.data.hostId) === ws) sockets.delete(ws.data.hostId);
      log(`xx ${ws.data.hostId ?? "?"} disconnected`);
    },
  },
});
log(`mock brain listening on 0.0.0.0:${PORT} (ws path /agent)`);
