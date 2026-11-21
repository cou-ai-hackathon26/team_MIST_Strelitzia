// Prohori brain: one Bun.serve for /agent (daemon WebSocket) and /api/* (dashboard HTTP API).
import { env } from "./env";
import { holdState, initHold, upsertSeedHost } from "./db";
import { websocketHandler, type WsData } from "./gateway";
import { handleApi } from "./api";
import { setRescanHook } from "./actions";
import { scheduleScans, startScan } from "./scan/runner";
import { scheduleWild } from "./wild";
import { ensureKev } from "./vuln/kev";
import "./mastra";

for (const h of env.seedHosts) upsertSeedHost(h.id, h.name, h.token);
initHold(env.replayHold);

let rescanTimer: Timer | null = null;
setRescanHook((reason) => {
  if (rescanTimer) clearTimeout(rescanTimer);
  // give the daemon a moment to send its refreshed inventory
  rescanTimer = setTimeout(() => startScan(reason, { queueIfBusy: true }), 8000);
});

const server = Bun.serve<WsData>({
  port: env.port,
  hostname: "0.0.0.0",
  idleTimeout: 255,
  async fetch(req, srv) {
    const url = new URL(req.url);
    if (url.pathname === "/agent") {
      if (srv.upgrade(req, { data: { hostId: null, connectedAt: Date.now() } })) return undefined;
      return new Response("WebSocket upgrade required", { status: 426 });
    }
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) return handleApi(req, url);
    if (url.pathname === "/health") return new Response("ok");
    return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
  },
  websocket: websocketHandler,
});

console.log(`[brain] listening on http://${server.hostname}:${server.port} (WS /agent, HTTP /api)`);
console.log(`[brain] seeded hosts: ${env.seedHosts.map((h) => h.id).join(", ") || "none"}; replay hold: ${JSON.stringify(holdState())}`);

void ensureKev();
scheduleScans();
scheduleWild();
setTimeout(() => startScan("startup"), env.firstScanDelayMs);

const shutdown = () => {
  console.log("[brain] shutting down");
  server.stop(true);
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
