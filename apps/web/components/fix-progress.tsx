"use client";

import { Loader2, RefreshCw } from "lucide-react";
import { actionTitle } from "@/lib/actions";
import { progressForAction, progressForHost, useFixProgress, type InProgress } from "@/lib/progress";
import { cn } from "@/lib/utils";

function label(p: InProgress, hostName: string): { text: string; tone: string; spin: "loader" | "refresh" } {
  const what = actionTitle(p.action, hostName);
  switch (p.phase) {
    case "applying":
      return { text: `Applying fix: ${what}…`, tone: "border-blue-500/40 bg-blue-500/10 text-blue-100", spin: "loader" };
    case "rolling_back":
      return { text: `Rolling back: ${what}…`, tone: "border-violet-500/40 bg-violet-500/10 text-violet-100", spin: "loader" };
    case "rechecking":
      return p.afterRollback
        ? { text: "Rolled back — Sentinel is re-checking this server…", tone: "border-violet-500/40 bg-violet-500/10 text-violet-100", spin: "refresh" }
        : { text: "Fix applied — Sentinel is re-checking this server…", tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-100", spin: "refresh" };
  }
}

function Chip({ p, hostName, compact, className }: { p: InProgress; hostName: string; compact?: boolean; className?: string }) {
  const l = label(p, hostName);
  const Icon = l.spin === "loader" ? Loader2 : RefreshCw;
  return (
    <div className={cn("inline-flex max-w-full items-center gap-1.5 rounded-md border px-2 py-1 text-xs", l.tone, className)} title={l.text}>
      <Icon className="size-3.5 shrink-0 animate-spin" />
      <span className={cn(compact && "truncate")}>{l.text}</span>
    </div>
  );
}

/** Shows "Applying fix… / re-checking…" for a host while a fix (or rollback) is in flight. Renders nothing otherwise. */
export function HostFixProgress({ hostId, hostName, compact, className }: { hostId: string; hostName: string; compact?: boolean; className?: string }) {
  const all = useFixProgress();
  const p = progressForHost(all, hostId);
  return p ? <Chip p={p} hostName={hostName} compact={compact} className={className} /> : null;
}

/** Same, for one specific action (used on action cards). */
export function ActionFixProgress({ actionId, hostName, className }: { actionId: string; hostName: string; className?: string }) {
  const all = useFixProgress();
  const p = progressForAction(all, actionId);
  return p ? <Chip p={p} hostName={hostName} className={className} /> : null;
}
