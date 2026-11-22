"use client";

import Link from "next/link";
import { use, useState } from "react";
import type { HostDetailResponse } from "@prohori/shared";
import { Cpu, Lock, Network, Package, Server, Settings2, ShieldBan } from "lucide-react";
import { Badge, Card, CardHeader, Empty, ErrorBanner, Input, KV, KevBadge, LiveTag, PageHeader, PriorityBadge, Skeleton, StatusPill } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { sortFindings } from "@/lib/format";
import { cn, fmtDate, relTime } from "@/lib/utils";

export default function HostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const now = useNow();
  const { data, error, updatedAt } = usePoll<HostDetailResponse>(`/hosts/${encodeURIComponent(id)}`, 5000);
  const [q, setQ] = useState("");
  const h = data?.host;
  const inv = data?.inventory;
  const pkgs = (inv?.packages ?? []).filter((p) => !q || `${p.name} ${p.version} ${p.source}`.toLowerCase().includes(q.toLowerCase()));
  const closedPorts = inv?.firewall?.closedPorts ?? [];
  const isBlocked = (port: number, proto: string) => closedPorts.some((r) => r.port === port && r.protocol === proto);
  const findings = (data?.findings ?? []).filter((f) => f.status !== "not_affected").sort(sortFindings);
  const configEntries = Object.entries(inv?.config ?? {}).sort(([a], [b]) => a.localeCompare(b));

  return (
    <>
      <PageHeader
        title={h?.name ?? id}
        icon={<Server className="size-6 text-blue-400" />}
        sub={h ? <span className="font-mono">{h.id} · {h.os ?? "Unknown OS"} · {h.status === "online" ? "Online" : "Offline"} · Last seen {relTime(h.lastSeen, now)}</span> : undefined}
        right={<LiveTag updatedAt={updatedAt} error={error} now={now} />}
      />
      <ErrorBanner error={error} />
      {!data ? (
        <Skeleton className="h-96" />
      ) : (
        <div className="space-y-5">
          <Card>
            <CardHeader title={`Findings (${findings.length})`} />
            {findings.length === 0 ? (
              <div className="p-4 text-sm text-muted">No open findings for this asset.</div>
            ) : (
              <table className="w-full text-sm">
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.id} className="border-t border-line/60 first:border-0 hover:bg-panel-2/50">
                      <td className="px-4 py-2"><PriorityBadge priority={f.priority} /></td>
                      <td className="px-4 py-2"><StatusPill status={f.status} /></td>
                      <td className="px-4 py-2"><Link href={`/findings/${f.id}`} className="font-mono font-semibold text-white hover:underline">{f.cveId}</Link> {f.inKev && <KevBadge className="ml-1" />}</td>
                      <td className="px-4 py-2 text-muted">{f.title}</td>
                      <td className="px-4 py-2 font-mono text-xs">{f.package ? `${f.package.name} ${f.package.installedVersion}` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          {!inv ? (
            <Empty>No inventory received from this asset.</Empty>
          ) : (
            <>
              <div className="grid gap-5 lg:grid-cols-2">
                <Card>
                  <CardHeader title="System" icon={<Cpu className="size-4 text-blue-400" />} sub={`Inventory collected ${relTime(inv.collectedAt, now)} (${fmtDate(inv.collectedAt)})`} />
                  <div className="px-4 py-2">
                    <KV k="Hostname" v={inv.hostname} />
                    <KV k="OS" v={`${inv.os.name} ${inv.os.version}`} />
                    <KV k="Codename" v={inv.os.codename} />
                    <KV k="Platform" v={inv.os.platform} />
                    <KV k="Daemon" v={h?.daemonVersion ?? "—"} />
                    <KV k="Packages" v={String(inv.packages.length)} />
                    <KV k="Processes" v={String(inv.processes.length)} />
                  </div>
                </Card>
                <Card>
                  <CardHeader title="Listening Ports" icon={<Network className="size-4 text-blue-400" />} sub="Network exposure as reported by osquery" />
                  {inv.listeningPorts.length === 0 ? (
                    <div className="p-4 text-sm text-emerald-300">No network listeners. No network attack surface.</div>
                  ) : (
                    <table className="w-full text-sm">
                      <thead className="text-left text-[11px] uppercase tracking-wider text-dim"><tr><th className="px-4 py-2">Address</th><th className="px-4 py-2">Protocol</th><th className="px-4 py-2">Process</th><th className="px-4 py-2">PID</th></tr></thead>
                      <tbody>
                        {inv.listeningPorts.map((p, i) => {
                          const pub = !["127.0.0.1", "::1"].includes(p.address);
                          return (
                            <tr key={i} className="border-t border-line/60 font-mono text-xs">
                              <td className={cn("px-4 py-1.5", isBlocked(p.port, p.protocol) ? "text-muted line-through" : pub ? "text-amber-300" : "text-muted")}>
                                {p.address}:{p.port}
                                {isBlocked(p.port, p.protocol) && <Badge tone="blue" className="ml-2 font-sans no-underline"><Lock className="size-3" /> Blocked by firewall</Badge>}
                              </td>
                              <td className="px-4 py-1.5 text-muted">{p.protocol}</td>
                              <td className="px-4 py-1.5">{p.process}</td>
                              <td className="px-4 py-1.5 text-dim">{p.pid}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </Card>
              </div>

              <Card>
                <CardHeader
                  title="Firewall"
                  icon={<ShieldBan className="size-4 text-blue-400" />}
                  sub="Ports closed by Sentinel-managed containment rules, approved by an administrator"
                  right={inv.firewall?.available ? <Badge tone="green">Firewall tooling available</Badge> : <Badge tone="gray">Firewall tooling unavailable</Badge>}
                />
                {closedPorts.length === 0 ? (
                  <div className="p-4 text-sm text-muted">No ports closed by Sentinel.</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="text-left text-[11px] uppercase tracking-wider text-dim"><tr><th className="px-4 py-2">Port</th><th className="px-4 py-2">State</th><th className="px-4 py-2">Managed By</th><th className="px-4 py-2">Action</th></tr></thead>
                    <tbody>
                      {closedPorts.map((r) => (
                        <tr key={`${r.port}/${r.protocol}`} className="border-t border-line/60 text-xs">
                          <td className="px-4 py-1.5 font-mono"><Lock className="mr-1 inline size-3 text-blue-300" />{r.port}/{r.protocol}</td>
                          <td className="px-4 py-1.5"><Badge tone="blue">{r.state}</Badge></td>
                          <td className="px-4 py-1.5 text-muted">{r.managedBy}</td>
                          <td className="px-4 py-1.5">{r.actionId ? <Link href="/approvals" className="font-mono text-blue-400 hover:underline">{r.actionId}</Link> : <span className="text-dim">—</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Card>

              <Card>
                <CardHeader title="Configuration" icon={<Settings2 className="size-4 text-blue-400" />} />
                <div className="px-4 py-2">
                  {configEntries.length === 0 ? <div className="py-2 text-sm text-muted">No configuration values reported.</div> : configEntries.map(([k, v]) => <KV key={k} k={<span className="font-mono text-xs" title={k}>{k}</span>} v={v} />)}
                </div>
              </Card>

              <Card>
                <CardHeader
                  title={`Installed Packages (${inv.packages.length})`}
                  icon={<Package className="size-4 text-blue-400" />}
                  right={<Input placeholder="Filter, e.g. php" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56 text-xs" />}
                />
                <div className="max-h-[480px] overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-panel text-left text-[11px] uppercase tracking-wider text-dim"><tr><th className="px-4 py-2">Package</th><th className="px-4 py-2">Version</th><th className="px-4 py-2">Source</th><th className="px-4 py-2">Arch</th></tr></thead>
                    <tbody>
                      {pkgs.slice(0, 500).map((p) => (
                        <tr key={`${p.name}:${p.arch}`} className="border-t border-line/50 font-mono text-xs">
                          <td className="px-4 py-1">{p.name}</td>
                          <td className="px-4 py-1 text-fg">{p.version}</td>
                          <td className="px-4 py-1 text-muted">{p.source}</td>
                          <td className="px-4 py-1 text-dim">{p.arch}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {pkgs.length > 500 && <div className="p-3 text-center text-xs text-muted">Showing 500 of {pkgs.length}. Refine the filter to narrow results.</div>}
                  {pkgs.length === 0 && <div className="p-4 text-center text-sm text-muted">No packages match.</div>}
                </div>
              </Card>
            </>
          )}
        </div>
      )}
    </>
  );
}
