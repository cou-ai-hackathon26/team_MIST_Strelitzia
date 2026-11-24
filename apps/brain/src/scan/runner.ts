// Scan orchestration: single-flight, cron schedule, cancellation, ScanState for the API.
import { Cron } from "croner";
import type { ScanState } from "@prohori/shared";
import { audit, getSettings, nowIso } from "../db";
import { scanContexts, scanWorkflow } from "./workflow";
import { markRechecked } from "../actions";
import type { ScanContext } from "./engine";

const state: ScanState = { running: false, lastStartedAt: null, lastFinishedAt: null, nextRunAt: null, lastResult: null };
let cron: Cron | null = null;
let followUp: string | null = null;
let currentRun: Promise<void> | null = null;
/** the scan that owns the single-flight slot; a cancelled scan gives it up at once, so its tail can't clobber a newer run */
let activeScanId: string | null = null;

export function scanState(): ScanState {
  return { ...state, nextRunAt: cron?.nextRun()?.toISOString() ?? null };
}

/** Starts a scan unless one is running. Returns whether it started. */
export function startScan(trigger: string, opts: { queueIfBusy?: boolean; actor?: string } = {}): boolean {
  if (!getSettings().cveScanEnabled) return false; // demo gate: CVE scanning is off until allowed in Settings
  if (state.running) {
    if (opts.queueIfBusy) followUp = trigger;
    return false;
  }
  const scanId = `scan_${Date.now().toString(36)}`;
  activeScanId = scanId;
  state.running = true;
  const startedAt = nowIso();
  state.lastStartedAt = startedAt;
  currentRun = runOnce(scanId, trigger, opts.actor ?? "prohori").finally(() => {
    if (activeScanId !== scanId) return; // cancelled: cancelScan() already released the slot
    activeScanId = null;
    state.running = false;
    state.lastFinishedAt = nowIso();
    try { markRechecked(startedAt); } catch (e) { console.error("[scan] markRechecked failed", e); }
    currentRun = null;
    if (followUp) {
      const t = followUp;
      followUp = null;
      setTimeout(() => startScan(t), 1000);
    }
  });
  return true;
}

export async function waitForScan() {
  await currentRun;
}

/**
 * Cancel the running scan (if any) and drop a queued follow-up. Used by environment resets: the scan stops at its next
 * check and never writes again (in-flight LLM calls are left to finish in the background and their results discarded).
 * The single-flight slot is released immediately, so a new scan can start right after the reset.
 */
export function cancelScan(): boolean {
  followUp = null;
  let cancelled = false;
  for (const ctx of scanContexts.values()) {
    if (!ctx.cancelled) { ctx.cancelled = true; cancelled = true; }
  }
  if (activeScanId) {
    activeScanId = null;
    state.running = false;
    state.lastFinishedAt = nowIso();
    state.lastResult = { newFindings: 0, changedFindings: 0, reportsSent: 0, error: "cancelled by an environment reset" };
    currentRun = null;
  }
  return cancelled;
}

async function runOnce(scanId: string, trigger: string, actor: string) {
  const ctx: ScanContext = {
    scanId, sessionId: `prohori-${scanId}-${crypto.randomUUID().slice(0, 8)}`, trigger, startedAt: nowIso(),
    hosts: [], matches: new Map(), rawMatchCount: {}, details: new Map(), triage: new Map(), candidates: [], evidence: new Map(),
    classified: [], newFindings: [], changedFindings: [], escalated: [], reportId: null, reportsSent: 0, proposedActions: 0, notes: [],
    cancelled: false,
  };
  scanContexts.set(scanId, ctx);
  audit("scan_started", `Scan started (${trigger.replace(/_/g, " ")})`, { actor, data: { scanId } });
  const t0 = Date.now();
  try {
    const run = await scanWorkflow.createRun();
    const result = await run.start({ inputData: { scanId } });
    if (ctx.cancelled) return; // the reset already wiped the event log; a cancelled scan leaves no trace
    if (result.status !== "success") {
      const err = result.status === "failed" ? (result.error as Error)?.message ?? String(result.error) : result.status;
      throw new Error(err);
    }
    state.lastResult = { newFindings: ctx.newFindings.length, changedFindings: ctx.changedFindings.length, reportsSent: ctx.reportsSent };
    const fresh = [...ctx.triage.entries()].filter(([, t]) => !t.cached);
    const triaged = fresh.length
      ? `; Sentinel triaged ${fresh.length} CVE(s) → ${fresh.filter(([, t]) => t.decision === "investigate").length} to investigate`
      : "";
    audit(
      "scan_finished",
      `Scan finished in ${((Date.now() - t0) / 1000).toFixed(1)}s: ${ctx.hosts.length} hosts checked, ${ctx.candidates.length} relevant CVE(s)${triaged}; ${ctx.newFindings.length} new, ${ctx.changedFindings.length} changed findings; ${ctx.reportsSent} report(s) sent; ${ctx.proposedActions} fix(es) proposed`,
      {
        data: {
          scanId, trigger, hosts: ctx.hosts.length, rawMatches: ctx.rawMatchCount, candidates: ctx.candidates.map((c) => `${c.cve} (${c.triage.decidedBy}: ${c.triage.reason})`),
          triage: Object.fromEntries(fresh.map(([c, t]) => [c, `${t.decision} (${t.decidedBy}): ${t.reason}`])),
          newFindings: ctx.newFindings.length, changedFindings: ctx.changedFindings.length, reportsSent: ctx.reportsSent,
          reportId: ctx.reportId, proposedActions: ctx.proposedActions, notes: ctx.notes,
        },
      },
    );
  } catch (e) {
    if (ctx.cancelled) return;
    const msg = (e as Error).message;
    state.lastResult = { newFindings: ctx.newFindings.length, changedFindings: ctx.changedFindings.length, reportsSent: ctx.reportsSent, error: msg };
    audit("error", `Scan failed: ${msg}`, { data: { scanId, notes: ctx.notes } });
    audit("scan_finished", `Scan failed after ${((Date.now() - t0) / 1000).toFixed(1)}s`, { data: { scanId, error: msg } });
  } finally {
    scanContexts.delete(scanId);
  }
}

export function scheduleScans() {
  cron?.stop();
  const sec = Math.max(10, getSettings().scanIntervalSec);
  cron = new Cron("* * * * * *", { interval: sec, protect: true, name: "prohori-scan", startAt: new Date(Date.now() + sec * 1000) }, () => {
    startScan("scheduled");
  });
}
