"use client";

import Link from "next/link";
import type { HostDetailResponse, HostSummary } from "@prohori/shared";
import { Cpu, Lock, Network, ScanLine, ShieldCheck, Wrench } from "lucide-react";
import { Badge, Card } from "@/components/ui";
import { usePoll } from "@/lib/api";
import { cn, relTime } from "@/lib/utils";
import { HostFixProgress } from "@/components/fix-progress";

export function HostCard({ host, now }: { host: HostSummary; now: number }) {
  // Inventory changes slowly; poll it less often than the status.
  const { data } = usePoll<HostDetailResponse>(`/hosts/${encodeURIComponent(host.id)}`, 10000);
  const inv = data?.inventory;
  const php = inv?.packages.filter((p) => p.source.startsWith("php") || /^php\d/.test(p.name)) ?? [];
  // Prefer the versioned runtime packages (php8.3-common/-fpm/-cli) over the "php"/"php-common" metapackages.
  const phpBuild =
    php.find((p) => /^php\d[\d.]*-common$/.test(p.name)) ??
    php.find((p) => /^php\d[\d.]*-(fpm|cli)$/.test(p.name)) ??
    php.find((p) => /^php\d/.test(p.name)) ??
    php[0];
  const phpSapis = [...new Set(php.map((p) => p.name.match(/^php[\d.]+-(fpm|cli|cgi)$/)?.[1]).filter(Boolean))];
  const ports = inv?.listeningPorts.filter((p) => p.protocol === "tcp" && !["127.0.0.1", "::1"].includes(p.address)) ?? [];
  const closed = inv?.firewall?.closedPorts ?? [];
  const c = host.findingCounts;
  const actionable = c.exposed + c.vulnerable_not_exposed;
  const online = host.status === "online";

  return (
    <Card
      className={cn(
        "flex flex-col overflow-hidden",
        c.exposed > 0 ? "border-red-500/60 shadow-[0_0_0_1px_rgba(239,68,68,0.25),0_0_30px_-10px_rgba(239,68,68,0.5)]" : c.vulnerable_not_exposed > 0 ? "border-amber-500/40" : "",
      )}
    >
      {c.exposed > 0 && <div className="bg-red-600 px-4 py-1 text-center text-[11px] font-bold uppercase tracking-widest text-white">Emergency · exposed</div>}
      <div className="flex items-start justify-between gap-2 px-4 pt-4">
        <div className="min-w-0">
          <Link href={`/hosts/${host.id}`} className="text-lg font-semibold text-white hover:underline">{host.name}</Link>
          <div className="font-mono text-xs text-dim">{host.id}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", online ? "text-emerald-300" : "text-slate-400")}>
            <span className={cn("size-2 rounded-full", online ? "bg-emerald-400 animate-pulse-dot" : "bg-slate-500")} />
            {online ? "online" : "offline"}
          </span>
          <span className="text-[11px] text-dim">seen {relTime(host.lastSeen, now)}</span>
        </div>
      </div>

      <div className="space-y-1.5 px-4 pt-3 text-xs">
        <div className="flex items-center gap-2 text-muted"><Cpu className="size-3.5" />{host.os ?? "unknown OS"}</div>
        {phpBuild ? (
          <div className="flex items-center gap-2 text-muted">
            <span className="w-3.5 text-center text-[10px] font-bold text-indigo-300">php</span>
            <span className="font-mono text-fg">{phpBuild.version}</span>
            {phpSapis.length > 0 && <span className="text-dim">({phpSapis.join(", ")})</span>}
          </div>
        ) : inv ? (
          <div className="flex items-center gap-2 text-dim"><span className="w-3.5 text-center text-[10px] font-bold">php</span>not installed</div>
        ) : null}
        {inv && (
          <div className="flex items-start gap-2 text-muted">
            <Network className="mt-0.5 size-3.5 shrink-0" />
            {closed.length > 0 && (
              <span className="inline-flex shrink-0 items-center gap-1 rounded border border-blue-500/40 bg-blue-500/15 px-1.5 font-mono text-[11px] text-blue-200" title="Closed by a Sentinel firewall rule">
                <Lock className="size-3" />{closed.map((r) => `${r.port}/${r.protocol}`).join(", ")} closed
              </span>
            )}
            {ports.length ? (
              <span className="font-mono text-fg">{ports.slice(0, 3).map((p) => `${p.address}:${p.port} ${p.process}`).join(", ")}{ports.length > 3 ? ` +${ports.length - 3}` : ""}</span>
            ) : (
              <span className="text-emerald-300/90">no network listeners</span>
            )}
          </div>
        )}
        <HostFixProgress hostId={host.id} hostName={host.name} compact className="mt-2" />
      </div>

      <div className="mt-4 grid grid-cols-3 gap-px border-y border-line bg-line text-center">
        {([
          ["exposed", c.exposed, "text-red-400", "Exposed"],
          ["vne", c.vulnerable_not_exposed, "text-amber-400", "Not exposed"],
          ["na", c.not_affected, "text-emerald-400", "Not affected"],
        ] as const).map(([k, n, cls, label]) => (
          <div key={k} className="bg-panel py-2">
            <div className={cn("text-xl font-bold tabular-nums", n > 0 ? cls : "text-dim")}>{n}</div>
            <div className="text-[10px] uppercase tracking-wider text-dim">{label}</div>
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between gap-2 px-4 py-2.5 text-xs">
        <span className="inline-flex items-center gap-1 text-muted" title="Raw OSV matches for this host's packages — what a version-number scanner would alert on">
          <ScanLine className="size-3.5" /> naive scanner: <b className="text-red-300 tabular-nums">{host.rawMatchCount}</b> raw alerts
        </span>
        <span className="inline-flex items-center gap-1 text-muted">
          <ShieldCheck className="size-3.5" /> Sentinel: <b className={cn("tabular-nums", c.exposed ? "text-red-400" : actionable ? "text-amber-300" : "text-emerald-300")}>{actionable}</b> to act on
        </span>
      </div>
      <div className="flex items-center gap-1.5 border-t border-line px-4 py-2 text-[11px] text-dim">
        {host.tier2Enabled ? (
          <Badge tone="violet"><Wrench className="size-3" /> Tier-2 fixes enabled</Badge>
        ) : (
          <Badge tone="gray">Tier-1 read-only</Badge>
        )}
        {host.daemonVersion && <span className="ml-auto font-mono">daemon {host.daemonVersion}</span>}
      </div>
    </Card>
  );
}
