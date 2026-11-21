"use client";

import Link from "next/link";
import type { HostDetailResponse, HostSummary } from "@prohori/shared";
import { Cpu, Lock, Network, Package } from "lucide-react";
import { Card } from "@/components/ui";
import { usePoll } from "@/lib/api";
import { cn, relTime } from "@/lib/utils";
import { HostFixProgress } from "@/components/fix-progress";
import { PRIORITY_RANK, STATUS_RANK, sortFindings } from "@/lib/format";

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
  // Most relevant package line: the package of the host's top affected finding (severity, then KEV); otherwise PHP
  // if installed; otherwise the package of a not-affected finding; else nothing.
  const ranked = [...(data?.findings ?? [])].filter((f) => f.package).sort((a, b) => PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] || STATUS_RANK[a.status] - STATUS_RANK[b.status] || Number(b.inKev) - Number(a.inKev) || sortFindings(a, b));
  const top = ranked[0];
  const topAffected = ranked.find((f) => f.status !== "not_affected");
  const pkgOf = (f: (typeof ranked)[number]) => ({ name: f.package!.name, version: f.package!.installedVersion, isPhp: /^php/i.test(f.package!.name) });
  const pkgLine: { name: string; version: string; isPhp: boolean } | null = topAffected
    ? pkgOf(topAffected)
    : phpBuild
      ? { name: "php", version: phpBuild.version, isPhp: true }
      : top
        ? pkgOf(top)
        : null;
  const ports = inv?.listeningPorts.filter((p) => p.protocol === "tcp" && !["127.0.0.1", "::1"].includes(p.address)) ?? [];
  const closed = inv?.firewall?.closedPorts ?? [];
  const c = host.findingCounts;
  const online = host.status === "online";

  return (
    <Card
      className={cn(
        "flex flex-col overflow-hidden",
        c.exposed > 0 ? "border-red-500/60 shadow-[0_0_0_1px_rgba(239,68,68,0.25),0_0_30px_-10px_rgba(239,68,68,0.5)]" : c.vulnerable_not_exposed > 0 ? "border-amber-500/40" : "",
      )}
    >
      {c.exposed > 0 && <div className="bg-red-600 px-4 py-1 text-center text-[11px] font-bold uppercase tracking-widest text-white">{top && top.priority !== "critical" ? "Exposed" : "Critical · Exposed"}</div>}
      <div className="flex items-start justify-between gap-2 px-4 pt-4">
        <div className="min-w-0">
          <Link href={`/hosts/${host.id}`} className="text-lg font-semibold text-white hover:underline">{host.name}</Link>
          <div className="font-mono text-xs text-dim">{host.id}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", online ? "text-emerald-300" : "text-slate-400")}>
            <span className={cn("size-2 rounded-full", online ? "bg-emerald-400 animate-pulse-dot" : "bg-slate-500")} />
            {online ? "Online" : "Offline"}
          </span>
          <span className="text-[11px] text-dim">Last seen {relTime(host.lastSeen, now)}</span>
        </div>
      </div>

      <div className="space-y-1.5 px-4 pt-3 text-xs">
        <div className="flex items-center gap-2 text-muted"><Cpu className="size-3.5" />{host.os ?? "Unknown OS"}</div>
        {pkgLine && (
          <div className="flex items-center gap-2 text-muted" title={pkgLine.isPhp ? "Installed PHP build" : "Package of this asset's top finding"}>
            {pkgLine.isPhp ? (
              <span className="w-3.5 text-center text-[10px] font-bold text-indigo-300">php</span>
            ) : (
              <Package className="size-3.5 shrink-0" />
            )}
            {!pkgLine.isPhp && <span className="text-muted">{pkgLine.name}</span>}
            <span className="min-w-0 truncate font-mono text-fg">{pkgLine.version}</span>
            {pkgLine.isPhp && phpSapis.length > 0 && <span className="text-dim">({phpSapis.join(", ")})</span>}
          </div>
        )}
        {inv && (
          <div className="flex items-start gap-2 text-muted">
            <Network className="mt-0.5 size-3.5 shrink-0" />
            {closed.length > 0 && (
              <span className="inline-flex shrink-0 items-center gap-1 rounded border border-blue-500/40 bg-blue-500/15 px-1.5 font-mono text-[11px] text-blue-200" title="Blocked by a Sentinel-managed firewall rule">
                <Lock className="size-3" />{closed.map((r) => `${r.port}/${r.protocol}`).join(", ")} blocked
              </span>
            )}
            {ports.length ? (
              <span className="font-mono text-fg">{ports.slice(0, 3).map((p) => `${p.address}:${p.port} ${p.process}`).join(", ")}{ports.length > 3 ? ` +${ports.length - 3}` : ""}</span>
            ) : (
              <span className="text-emerald-300/90">No network listeners</span>
            )}
          </div>
        )}
        <HostFixProgress hostId={host.id} hostName={host.name} compact className="mt-2" />
      </div>

      <div className="mt-4 grid grid-cols-3 gap-px border-t border-line bg-line text-center">
        {([
          ["exposed", c.exposed, "text-red-400", "Exposed"],
          ["vne", c.vulnerable_not_exposed, "text-amber-400", "Unreachable"],
          ["na", c.not_affected, "text-emerald-400", "Not Affected"],
        ] as const).map(([k, n, cls, label]) => (
          <div key={k} className="bg-panel py-2">
            <div className={cn("text-xl font-bold tabular-nums", n > 0 ? cls : "text-dim")}>{n}</div>
            <div className="text-[10px] uppercase tracking-wider text-dim">{label}</div>
          </div>
        ))}
      </div>

    </Card>
  );
}
