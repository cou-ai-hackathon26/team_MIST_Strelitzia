"use client";

// One shared poller for "fix in progress" state, so every host card / finding row / action card can show
// "Applying fix…" → "Re-checking…" without each component polling /api/actions on its own.
import { useSyncExternalStore } from "react";
import type { ActionRecord } from "@prohori/shared";
import { api } from "@/lib/api";

export type ProgressPhase = "applying" | "rolling_back" | "rechecking";
export interface InProgress {
  action: ActionRecord;
  phase: ProgressPhase;
  /** true when the action being re-checked was a rollback (state rolled_back) */
  afterRollback: boolean;
}

let snapshot: InProgress[] = [];
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;

async function load() {
  try {
    const actions = await api<ActionRecord[]>("/actions");
    const next: InProgress[] = [];
    for (const a of actions) {
      const ph = a.progress?.phase;
      if (ph === "applying" || ph === "rolling_back" || ph === "rechecking") {
        next.push({ action: a, phase: ph, afterRollback: a.state === "rolled_back" });
      }
    }
    if (JSON.stringify(next.map((x) => [x.action.id, x.phase, x.action.state])) !== JSON.stringify(snapshot.map((x) => [x.action.id, x.phase, x.action.state]))) {
      snapshot = next;
      listeners.forEach((l) => l());
    }
  } catch {
    /* keep last snapshot */
  }
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  if (!timer) {
    void load();
    timer = setInterval(() => { if (document.visibilityState === "visible") void load(); }, 2000);
    window.addEventListener("prohori:refresh", load);
  }
  return () => {
    listeners.delete(cb);
    if (!listeners.size && timer) {
      clearInterval(timer);
      timer = null;
      window.removeEventListener("prohori:refresh", load);
    }
  };
}

const EMPTY: InProgress[] = [];
export function useFixProgress(): InProgress[] {
  return useSyncExternalStore(subscribe, () => snapshot, () => EMPTY);
}

export function progressForHost(all: InProgress[], hostId: string): InProgress | null {
  return all.find((p) => p.action.hostId === hostId) ?? null;
}

export function progressForAction(all: InProgress[], actionId: string): InProgress | null {
  return all.find((p) => p.action.id === actionId) ?? null;
}
