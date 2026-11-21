import Link from "next/link";
import type { AuditEvent } from "@prohori/shared";
import {
  AlertTriangle, Bot, Bug, CheckCircle2, CircleUser, FilePlus2, LogIn, Mail, MessageSquare, Play, Power, RefreshCw, Server,
  Settings, ShieldAlert, Siren, Sparkles, Undo2, Wrench, XCircle, GitBranch,
} from "lucide-react";
import { EVENT_TONE, actorKind, actorLabel } from "@/lib/format";
import { cn, relTime } from "@/lib/utils";

export const EVENT_ICON: Partial<Record<AuditEvent["kind"], typeof Bug>> = {
  scan_started: Play,
  scan_finished: CheckCircle2,
  finding_new: ShieldAlert,
  finding_changed: Bug,
  cve_discovered: Siren,
  vulnerable_detected: ShieldAlert,
  report_generated: FilePlus2,
  report_sent: Mail,
  action_proposed: Wrench,
  action_revised: GitBranch,
  action_approved: CheckCircle2,
  action_rejected: XCircle,
  action_applied: CheckCircle2,
  action_failed: XCircle,
  action_rolled_back: Undo2,
  host_online: Power,
  host_offline: Power,
  inventory_changed: RefreshCw,
  demo_inject: Sparkles,
  settings_changed: Settings,
  wild_refreshed: RefreshCw,
  login: LogIn,
  error: AlertTriangle,
};

export function ActorChip({ actor }: { actor: string | undefined }) {
  const k = actorKind(actor);
  const Icon = k === "system" ? Bot : k === "daemon" ? Server : CircleUser;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 font-sans text-[11px] font-medium",
        k === "system" ? "border-blue-500/30 bg-blue-500/10 text-blue-200" : k === "daemon" ? "border-slate-500/30 bg-slate-500/10 text-slate-300" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
      )}
    >
      <Icon className="size-3" />
      {actorLabel(actor)}
    </span>
  );
}

export function eventThreadId(e: AuditEvent): string | null {
  const t = e.data?.threadId;
  return typeof t === "string" && t ? t : null;
}

export function ActivityFeed({ events, now }: { events: AuditEvent[]; now: number }) {
  if (events.length === 0) return <div className="px-4 py-6 text-center text-sm text-muted">No activity yet.</div>;
  return (
    <ul className="divide-y divide-line/60">
      {events.map((e) => {
        const Icon = EVENT_ICON[e.kind] ?? Bug;
        const thread = eventThreadId(e);
        return (
          <li key={e.id} className="flex gap-3 px-4 py-2.5">
            <Icon className={cn("mt-0.5 size-4 shrink-0", EVENT_TONE[e.kind] ?? "text-muted")} />
            <div className="min-w-0 flex-1">
              <div className="text-sm leading-snug text-fg">{e.message}</div>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-dim">
                <ActorChip actor={e.actor} />
                {e.hostId && <span className="whitespace-nowrap">{e.hostId}</span>}
                {e.cveId && <span className="whitespace-nowrap">{e.cveId}</span>}
                {thread && (
                  <Link href={`/chat?thread=${encodeURIComponent(thread)}`} className="inline-flex items-center gap-0.5 font-sans text-blue-400 hover:underline">
                    <MessageSquare className="size-3" /> discussion
                  </Link>
                )}
              </div>
            </div>
            <span className="shrink-0 text-[11px] text-dim" title={e.at}>{relTime(e.at, now)}</span>
          </li>
        );
      })}
    </ul>
  );
}
