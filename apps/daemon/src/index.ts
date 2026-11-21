// prohori-daemon: thin host agent wrapping osquery. Connects out to the brain over WebSocket.
import { BrainToDaemon, PROTOCOL_VERSION, TIMING, type DaemonToBrain } from "@prohori/shared";
import { ActionRunner } from "./actions";
import { changeFingerprint, collectSnapshot, runNamedQuery, setOsqueryi } from "./collect";
import { DAEMON_VERSION, loadConfig } from "./config";
import { log, warn } from "./log";

let cfg: ReturnType<typeof loadConfig>;
try {
  cfg = loadConfig();
} catch (e) {
  log("FATAL", (e as Error).message);
  process.exit(2);
}
setOsqueryi(cfg.osqueryi);
const actions = new ActionRunner(cfg.tier2, cfg.stateDir);

log(`prohori-daemon ${DAEMON_VERSION} host=${cfg.hostId} brain=${cfg.brainUrl} tier2=${cfg.tier2} osqueryi=${cfg.osqueryi}`);

let ws: WebSocket | null = null;
let timers: ReturnType<typeof setInterval>[] = [];
let attempt = 0;
let lastFingerprint = "";
let welcomed = false;

type Outgoing = DaemonToBrain extends infer M ? (M extends { id: string } ? Omit<M, "id"> : never) : never;

function send(msg: Outgoing) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  ws.send(JSON.stringify({ id: crypto.randomUUID(), ...msg }));
  return true;
}

async function sendInventory(reason: "connect" | "periodic" | "changed") {
  try {
    const snapshot = await collectSnapshot();
    lastFingerprint = await changeFingerprint();
    send({ type: "inventory", reason, snapshot: snapshot as unknown as Record<string, unknown> });
    log(`inventory sent (${reason}): ${snapshot.packages.length} packages, ${snapshot.listeningPorts.length} listeners, ${Object.keys(snapshot.config).length} config keys`);
  } catch (e) {
    warn(`inventory collection failed: ${(e as Error).message}`);
  }
}

let checking = false;
async function changeCheck() {
  if (checking) return;
  checking = true;
  try {
    const fp = await changeFingerprint();
    if (lastFingerprint && fp !== lastFingerprint) {
      log("change detected (packages/listeners/config)");
      await sendInventory("changed");
    }
  } catch (e) {
    warn(`change check failed: ${(e as Error).message}`);
  } finally {
    checking = false;
  }
}

function clearTimers() {
  for (const t of timers) clearInterval(t);
  timers = [];
}

async function handle(raw: string) {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    warn("ignoring non-JSON message");
    return;
  }
  const parsed = BrainToDaemon.safeParse(json);
  if (!parsed.success) {
    warn(`ignoring invalid message: ${raw.slice(0, 200)}`);
    return;
  }
  const msg = parsed.data;
  switch (msg.type) {
    case "welcome": {
      welcomed = true;
      attempt = 0;
      log(`welcome: heartbeat=${msg.heartbeatSec}s inventory=${msg.inventorySec}s`);
      clearTimers();
      timers.push(setInterval(() => send({ type: "heartbeat", at: new Date().toISOString() }), Math.max(1, msg.heartbeatSec) * 1000));
      timers.push(setInterval(() => void sendInventory("periodic"), Math.max(5, msg.inventorySec) * 1000));
      timers.push(setInterval(() => void changeCheck(), TIMING.changeCheckSec * 1000));
      await sendInventory("connect");
      break;
    }
    case "reject":
      log(`rejected by brain: ${msg.reason}`);
      process.exit(1);
    case "query": {
      log(`query ${msg.name} (request ${msg.requestId})`);
      try {
        const rows = await runNamedQuery(msg.name);
        send({ type: "query_result", requestId: msg.requestId, ok: true, rows });
      } catch (e) {
        send({ type: "query_result", requestId: msg.requestId, ok: false, error: (e as Error).message });
      }
      break;
    }
    case "refresh":
      log("refresh requested");
      await sendInventory("periodic");
      break;
    case "action": {
      const r = await actions.apply(msg.actionId, msg.actionType, msg.params);
      log(`action ${msg.actionId} (${msg.actionType}) ok=${r.ok}${r.diff ? `\n${r.diff}` : ` ${r.output.slice(0, 200)}`}`);
      send({ type: "action_result", actionId: msg.actionId, kind: "apply", ok: r.ok, diff: r.diff, output: r.output });
      if (r.ok) void changeCheck();
      break;
    }
    case "rollback": {
      const r = await actions.rollback(msg.actionId);
      log(`rollback ${msg.actionId} ok=${r.ok}${r.diff ? `\n${r.diff}` : ` ${r.output.slice(0, 200)}`}`);
      send({ type: "action_result", actionId: msg.actionId, kind: "rollback", ok: r.ok, diff: r.diff, output: r.output });
      if (r.ok) void changeCheck();
      break;
    }
  }
}

function scheduleReconnect() {
  clearTimers();
  ws = null;
  const delay = Math.min(TIMING.reconnectMaxSec, 2 ** Math.min(attempt, 10)) * 1000;
  attempt++;
  log(`reconnecting in ${delay / 1000}s`);
  setTimeout(connect, delay);
}

function connect() {
  welcomed = false;
  log(`connecting to ${cfg.brainUrl}`);
  let sock: WebSocket;
  try {
    sock = new WebSocket(cfg.brainUrl);
  } catch (e) {
    warn(`connect failed: ${(e as Error).message}`);
    scheduleReconnect();
    return;
  }
  ws = sock;
  const welcomeTimer = setTimeout(() => {
    if (!welcomed && sock.readyState === WebSocket.OPEN) {
      warn("no welcome within 15s; closing");
      sock.close();
    }
  }, 15_000);
  sock.addEventListener("open", () => {
    log("connected; sending hello");
    send({
      type: "hello",
      hostId: cfg.hostId,
      token: cfg.token,
      daemonVersion: DAEMON_VERSION,
      protocolVersion: PROTOCOL_VERSION,
      tier2Enabled: cfg.tier2,
    });
  });
  sock.addEventListener("message", (ev) => {
    const data = typeof ev.data === "string" ? ev.data : Buffer.from(ev.data as ArrayBuffer).toString("utf8");
    handle(data).catch((e) => warn(`handler error: ${(e as Error).message}`));
  });
  sock.addEventListener("error", () => warn("websocket error"));
  sock.addEventListener("close", (ev) => {
    clearTimeout(welcomeTimer);
    if (ws !== sock) return;
    log(`disconnected (code ${ev.code}${ev.reason ? ` ${ev.reason}` : ""})`);
    scheduleReconnect();
  });
}

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    log(`${sig}; exiting`);
    process.exit(0);
  });
}

actions
  .reconcileFirewall()
  .catch((e) => warn(`firewall reconcile failed: ${(e as Error).message}`))
  .finally(connect);
