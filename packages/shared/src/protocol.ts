import { z } from "zod";
import { QUERY_NAMES } from "./queries";
import { ACTION_TYPES } from "./actions";

// WebSocket protocol between prohori-daemon (client) and brain (server).
// Endpoint: ws(s)://<BRAIN_HOST>:4400/agent
// Every message is one JSON object with a "type" and an "id" (unique per message, e.g. crypto.randomUUID()).
// Auth: the FIRST message from the daemon must be `hello`. The brain answers `welcome` or `reject` (then closes).

export const PROTOCOL_VERSION = 1;

const base = { id: z.string() };

// ---------- daemon -> brain ----------
export const HelloMsg = z.object({
  ...base,
  type: z.literal("hello"),
  hostId: z.string(),
  token: z.string(),
  daemonVersion: z.string(),
  protocolVersion: z.literal(PROTOCOL_VERSION),
});

export const HeartbeatMsg = z.object({ ...base, type: z.literal("heartbeat"), at: z.string() });

// Inventory payload is validated loosely here; see InventorySnapshot in domain.ts for the exact shape.
export const InventoryMsg = z.object({
  ...base,
  type: z.literal("inventory"),
  reason: z.enum(["connect", "periodic", "changed"]),
  snapshot: z.record(z.string(), z.unknown()),
});

export const QueryResultMsg = z.object({
  ...base,
  type: z.literal("query_result"),
  requestId: z.string(),
  ok: z.boolean(),
  rows: z.array(z.record(z.string(), z.unknown())).optional(),
  error: z.string().optional(),
});

export const ActionResultMsg = z.object({
  ...base,
  type: z.literal("action_result"),
  actionId: z.string(),
  kind: z.enum(["apply", "rollback"]),
  ok: z.boolean(),
  diff: z.string(),   // human-readable before/after
  output: z.string(), // command output (truncated to ~8KB)
});

export const DaemonToBrain = z.discriminatedUnion("type", [HelloMsg, HeartbeatMsg, InventoryMsg, QueryResultMsg, ActionResultMsg]);
export type DaemonToBrain = z.infer<typeof DaemonToBrain>;

// ---------- brain -> daemon ----------
export const WelcomeMsg = z.object({ ...base, type: z.literal("welcome"), heartbeatSec: z.number(), inventorySec: z.number() });
export const RejectMsg = z.object({ ...base, type: z.literal("reject"), reason: z.string() });

export const QueryMsg = z.object({
  ...base,
  type: z.literal("query"),
  requestId: z.string(),
  name: z.enum(QUERY_NAMES),
  /** Only for `config_file`: { path } — must match CONFIG_PATHS on the daemon. */
  params: z.record(z.string(), z.string()).optional(),
});

export const ActionMsg = z.object({
  ...base,
  type: z.literal("action"),
  actionId: z.string(),
  actionType: z.enum(ACTION_TYPES as [string, ...string[]]),
  params: z.record(z.string(), z.unknown()), // daemon re-validates with ActionParams[actionType]
});

export const RollbackMsg = z.object({ ...base, type: z.literal("rollback"), actionId: z.string() });

/** Ask the daemon to send a fresh inventory now (e.g. after an action or on "Scan now"). */
export const RefreshMsg = z.object({ ...base, type: z.literal("refresh") });

export const BrainToDaemon = z.discriminatedUnion("type", [WelcomeMsg, RejectMsg, QueryMsg, ActionMsg, RollbackMsg, RefreshMsg]);
export type BrainToDaemon = z.infer<typeof BrainToDaemon>;

export const TIMING = {
  heartbeatSec: 10,
  inventorySec: 120,        // periodic full inventory
  changeCheckSec: 15,       // daemon re-runs `packages` + `listening_ports` and sends inventory reason=changed if different
  queryTimeoutMs: 10_000,   // brain gives up waiting for query_result
  offlineAfterSec: 30,      // brain marks host offline after no heartbeat
  reconnectMaxSec: 30,      // daemon exponential backoff cap
};
