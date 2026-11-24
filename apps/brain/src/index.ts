// Prohori brain: one Bun.serve for /agent (daemon WebSocket) and /api/* (dashboard HTTP API).
import { env } from "./env";
import { holdState, initHold, listActions, upsertSeedHost } from "./db";
import { websocketHandler, type WsData } from "./gateway";
import { handleApi } from "./api";
import { setRescanHook } from "./actions";
import { scheduleScans, startScan } from "./scan/runner";
import { requestRecheck } from "./scan/recheck";
import { scheduleWild } from "./wild";
import { ensureKev } from "./vuln/kev";
import "./mastra";

for (const h of env.seedHosts) upsertSeedHost(h.id, h.name, h.token);
initHold(env.replayHold);

// After an action result: targeted re-check of that host only (waits for the refreshed inventory; works with
// scanning switched off). Scheduled scans still cover everything else.
setRescanHook((reason, hostId, sinceMs) => requestRecheck(hostId, reason, sinceMs));

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
// actions left "re-assessing" by a restart (or by the old scan-only re-check) get their re-check now
setTimeout(() => {
  for (const a of listActions()) {
    if (a.progress?.phase === "rechecking") requestRecheck(a.hostId, "re-check pending since before a restart", Date.parse(a.progress.resultAt ?? a.progress.since));
  }
}, 3000);

const shutdown = () => {
  console.log("[brain] shutting down");
  server.stop(true);
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
