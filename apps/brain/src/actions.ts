// Remediation action lifecycle: propose (agent/user) → [revise in chat] → approve (human, HTTP only) → daemon →
// applied/failed → rollback. Every human decision records the actor, an optional note and the chat thread.
import { ActionParams, type ActionRecord, type ActionType } from "@prohori/shared";
import { audit, getAction, getHostRow, listActions, newId, nowIso, saveAction } from "./db";
import { gatewayHooks, isOnline, requestRefresh, sendAction, sendRollback } from "./gateway";

export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

let rescanHook: (reason: string) => void = () => {};
export function setRescanHook(fn: (reason: string) => void) { rescanHook = fn; }

const hostName = (id: string) => getHostRow(id)?.name ?? id;

/** Human description, e.g. "close 80/tcp on bank-web-01". */
export function describeAction(a: Pick<ActionRecord, "type" | "params" | "hostId">): string {
  const p = a.params as any;
  const on = ` on ${hostName(a.hostId)}`;
  switch (a.type) {
    case "firewall_port": return `${p.state === "open" ? "re-open" : "close"} ${p.port}/${p.protocol}${on}`;
    case "upgrade_packages": return `upgrade ${(p.packages ?? []).join(", ")}${on}`;
    case "nginx_block_multipart": return `block multipart uploads in nginx${on}`;
    case "set_php_directive": return `set ${p.directive}=${p.value} for PHP ${p.sapi}${on}`;
    case "set_config_directive": return `set ${p.directive} ${p.value} in ${p.file}${on}`;
    case "restart_service": return `restart ${p.service}${on}`;
    default: return `${a.type}${on}`;
  }
}

function decisionSuffix(note?: string | null, threadId?: string | null) {
  return `${note ? ` — note: '${note}'` : ""}${threadId ? ` (thread ${threadId})` : ""}`;
}

function validate(type: ActionType, params: unknown) {
  const schema = ActionParams[type];
  if (!schema) throw new HttpError(400, `unknown action type ${type}`);
  const parsed = schema.safeParse(params ?? {});
  if (!parsed.success) throw new HttpError(400, `invalid params for ${type}: ${parsed.error.issues.map((i) => i.message).join("; ")}`);
  return parsed.data as Record<string, unknown>;
}

export function proposeAction(input: {
  hostId: string; findingId?: string | null; type: ActionType; params: unknown; reason: string; proposedBy: "agent" | "user";
  threadId?: string | null; supersedes?: string | null; actor?: string;
}): ActionRecord {
  if (!getHostRow(input.hostId)) throw new HttpError(404, `unknown host ${input.hostId}`);
  const params = validate(input.type, input.params);
  // Never create a duplicate: if an identical proposal is already pending (or approved/running/applied),
  // return that one instead (and attach this chat thread if it has none).
  if (!input.supersedes) {
    // one-off actions (restarts) only dedupe against ones that haven't run yet
    const states = input.type === "restart_service" ? ["pending", "approved", "running"] : ["pending", "approved", "running", "applied"];
    const existing = findEquivalent(input.hostId, input.type, params, states);
    if (existing) {
      if (!existing.threadId && input.threadId) { existing.threadId = input.threadId; saveAction(existing); }
      return existing;
    }
  }
  const a: ActionRecord = {
    id: newId("act"),
    hostId: input.hostId,
    findingId: input.findingId ?? null,
    type: input.type,
    params,
    reason: input.reason,
    state: "pending",
    proposedBy: input.proposedBy,
    createdAt: nowIso(),
    decidedAt: null,
    decidedBy: null,
    decisionNote: null,
    threadId: input.threadId ?? null,
    supersedes: input.supersedes ?? null,
    supersededBy: null,
    rolledBackBy: null,
    result: null,
    progress: null,
  };
  saveAction(a);
  if (!input.supersedes) {
    audit("action_proposed", `${input.proposedBy === "agent" ? "Sentinel" : input.actor ?? "admin"} proposed: ${describeAction(a)} — ${input.reason}`, {
      hostId: a.hostId, actor: input.actor ?? "prohori", data: { actionId: a.id, type: a.type, params: a.params, threadId: a.threadId },
    });
  }
  return a;
}

/** Replace a PENDING proposal with a new pending one (chat review). The old one becomes "superseded". */
export function reviseAction(oldId: string, input: { type: ActionType; params: unknown; reason: string; threadId: string | null; requestedBy?: string }): ActionRecord {
  const old = must(oldId);
  if (old.state !== "pending") throw new HttpError(409, `action is ${old.state}; only pending proposals can be revised`);
  const next = proposeAction({
    hostId: old.hostId, findingId: old.findingId, type: input.type, params: input.params, reason: input.reason,
    proposedBy: "agent", threadId: input.threadId ?? old.threadId, supersedes: old.id,
  });
  old.state = "superseded";
  old.supersededBy = next.id;
  old.threadId ??= next.threadId;
  saveAction(old);
  audit("action_revised", `Sentinel revised proposal: ${describeAction(old)} → ${describeAction(next)}${input.requestedBy ? ` (requested by ${input.requestedBy})` : ""}${decisionSuffix(null, next.threadId)} — ${input.reason}`, {
    hostId: old.hostId, actor: "prohori", data: { actionId: next.id, oldActionId: old.id, newActionId: next.id, threadId: next.threadId, requestedBy: input.requestedBy },
  });
  return next;
}

const paramKey = (p: Record<string, unknown>) =>
  JSON.stringify(p, Object.keys(p).sort(), 0) + "|" + JSON.stringify(Array.isArray((p as any).packages) ? [...(p as any).packages].sort() : null);

function findEquivalent(hostId: string, type: ActionType, params: Record<string, unknown>, states: string[]): ActionRecord | null {
  const key = paramKey(params);
  return listActions({ hostId }).find((a) =>
    a.type === type && states.includes(a.state) && paramKey(a.params) === key &&
    // a proposal closed only because its finding resolved (no successor) must not block re-proposing later
    !(a.state === "superseded" && !a.supersededBy)) ?? null;
}

/** True if an equivalent action is already pending/approved/running/applied. */
export function hasEquivalentAction(
  hostId: string, type: ActionType, params: Record<string, unknown>,
  states = ["pending", "approved", "running", "applied"],
): boolean {
  return !!findEquivalent(hostId, type, params, states);
}

/** Two proposals do the same job on a host: same type, and for firewall_port the same port/protocol. */
function sameJob(a: ActionRecord, b: ActionRecord): boolean {
  if (a.hostId !== b.hostId || a.type !== b.type) return false;
  if (a.type === "firewall_port") {
    const p = a.params as any, q = b.params as any;
    return p.port === q.port && p.protocol === q.protocol;
  }
  if (a.type === "set_php_directive") {
    const p = a.params as any, q = b.params as any;
    return p.sapi === q.sapi && p.directive === q.directive;
  }
  if (a.type === "set_config_directive") {
    const p = a.params as any, q = b.params as any;
    return p.file === q.file && p.directive === q.directive;
  }
  return true; // other action types: same type on the same host = the same job
}

/** Close a pending proposal without a human decision (duplicate or no longer needed). */
function closeProposal(p: ActionRecord, why: string, supersededBy: string | null) {
  p.state = "superseded";
  p.supersededBy = supersededBy;
  p.decidedAt = nowIso();
  p.decidedBy = null;
  p.decisionNote = why;
  saveAction(p);
  audit("action_revised", `Closed proposal: ${describeAction(p)} — ${why}`, {
    hostId: p.hostId, actor: "prohori", data: { actionId: p.id, threadId: p.threadId, newActionId: supersededBy },
  });
}

/** After a scan: pending proposals whose finding is no longer exposed/vulnerable are closed automatically. */
export function closeObsoleteProposals(findingStatus: (findingId: string) => string | null): number {
  let n = 0;
  for (const p of listActions({ state: "pending" })) {
    if (!p.findingId) continue;
    const st = findingStatus(p.findingId);
    if (st === "not_affected" || st === null) {
      closeProposal(p, st === null ? "no longer needed: the finding no longer exists" : "no longer needed: the finding is resolved (host not affected)", null);
      n++;
    }
  }
  return n;
}

function must(id: string): ActionRecord {
  const a = getAction(id);
  if (!a) throw new HttpError(404, "action not found");
  return a;
}

/**
 * Called when a scan finishes. Actions waiting for a re-check become "done" once a scan that STARTED after the
 * daemon's result (plus a small margin for the refreshed inventory to arrive) has finished.
 */
export function markRechecked(scanStartedAt: string) {
  const started = Date.parse(scanStartedAt);
  for (const a of listActions()) {
    if (a.progress?.phase !== "rechecking" || !a.progress.resultAt) continue;
    if (started >= Date.parse(a.progress.resultAt) + 2000) {
      a.progress = { ...a.progress, phase: "done", since: nowIso() };
      saveAction(a);
    }
  }
}

export interface Decision { actor: string; note?: string | null; threadId?: string | null }

export function approveAction(id: string, d: Decision): ActionRecord {
  const a = must(id);
  if (a.state !== "pending") throw new HttpError(409, `action is ${a.state}, only pending actions can be approved`);
  const host = getHostRow(a.hostId);
  if (!host) throw new HttpError(404, "host not found");
  if (!isOnline(a.hostId)) throw new HttpError(409, `${host.name} is offline`);
  a.state = "approved";
  a.decidedAt = nowIso();
  a.decidedBy = d.actor;
  a.decisionNote = d.note || null;
  if (d.threadId) a.threadId = d.threadId;
  saveAction(a);
  audit("action_approved", `${d.actor} approved: ${describeAction(a)}${decisionSuffix(a.decisionNote, a.threadId)}`, {
    hostId: a.hostId, actor: d.actor, data: { actionId: a.id, note: a.decisionNote, threadId: a.threadId },
  });
  for (const other of listActions({ hostId: a.hostId, state: "pending" })) {
    if (other.id !== a.id && sameJob(other, a)) closeProposal(other, `duplicate of the approved proposal ${a.id} (approved by ${d.actor})`, a.id);
  }
  try {
    sendAction(a.hostId, a.id, a.type, a.params);
    a.state = "running";
    a.progress = { phase: "applying", since: nowIso(), resultAt: null };
  } catch (e) {
    a.state = "failed";
    a.progress = { phase: "done", since: nowIso(), resultAt: null };
    a.result = { ok: false, diff: "", output: `could not send to daemon: ${(e as Error).message}` };
    audit("action_failed", `${describeAction(a)}: ${(e as Error).message}`, { hostId: a.hostId, data: { actionId: a.id } });
  }
  saveAction(a);
  return a;
}

export function rejectAction(id: string, d: Decision): ActionRecord {
  const a = must(id);
  if (a.state !== "pending") throw new HttpError(409, `action is ${a.state}, only pending actions can be rejected`);
  a.state = "rejected";
  a.decidedAt = nowIso();
  a.decidedBy = d.actor;
  a.decisionNote = d.note || null;
  if (d.threadId) a.threadId = d.threadId;
  saveAction(a);
  audit("action_rejected", `${d.actor} rejected: ${describeAction(a)}${decisionSuffix(a.decisionNote, a.threadId)}`, {
    hostId: a.hostId, actor: d.actor, data: { actionId: a.id, note: a.decisionNote, threadId: a.threadId },
  });
  return a;
}

export function rollbackAction(id: string, d: Decision): ActionRecord {
  const a = must(id);
  if (a.state !== "applied") throw new HttpError(409, `action is ${a.state}, only applied actions can be rolled back`);
  if (!isOnline(a.hostId)) throw new HttpError(409, `${hostName(a.hostId)} is offline`);
  sendRollback(a.hostId, a.id);
  a.rolledBackBy = d.actor;
  a.progress = { phase: "rolling_back", since: nowIso(), resultAt: null };
  saveAction(a);
  audit("action_approved", `${d.actor} requested rollback: ${describeAction(a)}${decisionSuffix(d.note, a.threadId)}`, {
    hostId: a.hostId, actor: d.actor, data: { actionId: a.id, rollback: true, note: d.note ?? null },
  });
  return a;
}

gatewayHooks.onActionResult = async (m) => {
  const a = getAction(m.actionId);
  if (!a) return;
  const actor = `daemon:${a.hostId}`;
  const result = { ok: m.ok, diff: m.diff, output: m.output };
  const at = nowIso();
  a.progress = { phase: "rechecking", since: at, resultAt: at };
  if (m.kind === "apply") {
    a.state = m.ok ? "applied" : "failed";
    a.result = result;
    saveAction(a);
    audit(m.ok ? "action_applied" : "action_failed", `${describeAction(a)} ${m.ok ? "applied" : "failed"}${m.diff ? `: ${m.diff.split("\n")[0]}` : ""}`, {
      hostId: a.hostId, actor, data: { actionId: a.id, diff: m.diff },
    });
  } else {
    if (m.ok) a.state = "rolled_back";
    a.result = result;
    saveAction(a);
    audit(m.ok ? "action_rolled_back" : "action_failed", `rollback of ${describeAction(a)} ${m.ok ? "done" : "failed"}${a.rolledBackBy ? ` (requested by ${a.rolledBackBy})` : ""}`, {
      hostId: a.hostId, actor, data: { actionId: a.id, diff: m.diff },
    });
  }
  requestRefresh(a.hostId);
  rescanHook(`after ${m.kind} of ${a.type} on ${a.hostId}`);
};
