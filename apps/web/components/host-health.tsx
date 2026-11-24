"use client";

import Link from "next/link";
import type { HostHealth, HostSummary } from "@prohori/shared";
import { AlertOctagon, ServerCrash, WifiOff } from "lucide-react";
import { Button } from "@/components/ui";
import { cn, relTime } from "@/lib/utils";

/** Hosts whose daemon is down / silent / stale and an admin should look at (excludes "still connecting"). */
export const alertHosts = (hosts: HostSummary[]) => hosts.filter((h) => h.health?.state === "unassessable" && h.health.alert);
/** Hosts Sentinel cannot assess right now, alerting or not. */
export const unassessable = (hosts: HostSummary[]) => hosts.filter((h) => h.health?.state === "unassessable");

const KIND_LABEL: Record<NonNullable<HostHealth["kind"]>, string> = {
  offline: "Daemon not responding",
  stale: "Inventory stale",
  never_reported: "Not reporting yet",
};

export function HealthBanner({ hosts, now }: { hosts: HostSummary[]; now: number }) {
  const bad = alertHosts(hosts);
  if (!bad.length) return null;
  return (
    <div role="alert" className="mb-5 rounded-xl border border-orange-500/60 bg-gradient-to-r from-orange-950/80 to-orange-950/20 px-5 py-4">
      <div className="flex flex-wrap items-center gap-3">
        <ServerCrash className="size-7 shrink-0 text-orange-400" />
        <div className="min-w-0 flex-1">
          <div className="font-display text-lg text-white">
            {bad.length === 1 ? "1 server cannot be assessed" : `${bad.length} servers cannot be assessed`}
          </div>
          <div className="text-sm text-orange-100/80">
            Sentinel is not proposing or approving any fix for {bad.length === 1 ? "it" : "them"} until the daemon reports again. Investigate the server{bad.length === 1 ? "" : "s"} below.
          </div>
        </div>
      </div>
      <ul className="mt-3 space-y-1.5">
        {bad.map((h) => (
          <li key={h.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg bg-black/25 px-3 py-2 text-sm">
            <WifiOff className="size-4 shrink-0 text-orange-300" />
            <Link href={`/hosts/${h.id}`} className="font-semibold text-white hover:underline">{h.name}</Link>
            <span className="text-orange-100/90">{h.health!.reason}</span>
            <span className="text-xs text-orange-200/60">last inventory {relTime(h.health!.lastInventoryAt, now)}</span>
            <Link href={`/hosts/${h.id}`} className="ml-auto"><Button variant="danger" size="sm">Investigate</Button></Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Small pill for host cards / headers. */
export function HealthPill({ health, className }: { health: HostHealth | undefined; className?: string }) {
  if (!health || health.state === "ok") return null;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
        health.alert ? "border-orange-500/60 bg-orange-500/15 text-orange-200" : "border-slate-500/40 bg-slate-500/15 text-slate-300",
        className,
      )}
      title={health.reason}
    >
      <AlertOctagon className="size-3" />
      {health.kind ? (health.alert ? KIND_LABEL[health.kind] : "Not reporting yet") : "Cannot assess"}
    </span>
  );
}

/** Explanation panel on the host page. */
export function HealthPanel({ host, now }: { host: HostSummary; now: number }) {
  const h = host.health;
  if (!h || h.state === "ok") return null;
  return (
    <div role="alert" className={cn("rounded-xl border px-5 py-4", h.alert ? "border-orange-500/60 bg-orange-950/40" : "border-slate-500/40 bg-slate-900/60")}>
      <div className="flex items-center gap-2 font-display text-lg text-white">
        <ServerCrash className={cn("size-6", h.alert ? "text-orange-400" : "text-slate-400")} />
        {h.alert ? "This server cannot be assessed — investigate" : "Waiting for this server to report"}
      </div>
      <p className="mt-2 text-sm text-fg">{h.reason}.</p>
      <dl className="mt-3 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-3">
        <div><dt className="text-xs uppercase tracking-wider text-dim">Last heartbeat</dt><dd>{relTime(host.lastSeen, now)}</dd></div>
        <div><dt className="text-xs uppercase tracking-wider text-dim">Last inventory</dt><dd>{relTime(h.lastInventoryAt, now)}</dd></div>
        <div><dt className="text-xs uppercase tracking-wider text-dim">Daemon</dt><dd>{host.status === "online" ? "Connected" : "Not connected"}</dd></div>
      </dl>
      <div className="mt-3 text-sm text-muted">
        Sentinel proposes <b className="text-fg">no fixes</b>, runs <b className="text-fg">no scans</b> and refuses <b className="text-fg">approvals</b> for this server while its inventory cannot be trusted; existing findings below may be out of date.
      </div>
      <ul className="mt-3 list-disc space-y-0.5 pl-5 text-sm text-muted">
        <li>Is the <code className="font-mono text-fg">prohori-daemon</code> process running on the server, and can it reach the brain?</li>
        <li>Is <code className="font-mono text-fg">osqueryi</code> installed and working? A broken osquery keeps the daemon alive but stops inventory.</li>
        <li>Is the server up and its clock correct?</li>
      </ul>
    </div>
  );
}
