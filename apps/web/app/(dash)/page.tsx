"use client";

import Link from "next/link";
import { useState } from "react";
import type { Finding, ScanState, StatusResponse } from "@prohori/shared";
import { Activity, AlertOctagon, Loader2, Radar, ScanLine, ShieldCheck } from "lucide-react";
import { ActivityFeed } from "@/components/activity";
import { ContrastTable } from "@/components/contrast";
import { HostCard } from "@/components/host-card";
import { Button, Card, CardHeader, Empty, ErrorBanner, KevBadge, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { api, useNow, usePoll } from "@/lib/api";
import { groupByCve } from "@/lib/format";
import { cn, relTime } from "@/lib/utils";

function ScanStrip({ scan, onScan, busy, now }: { scan: ScanState; onScan: () => void; busy: boolean; now: number }) {
  const r = scan.lastResult;
  return (
    <Card className="mb-5 flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        {scan.running ? <Loader2 className="size-4 animate-spin text-blue-400" /> : <Radar className="size-4 text-blue-400" />}
        {scan.running ? <span className="text-blue-300">Scan running… (started {relTime(scan.lastStartedAt, now)})</span> : <span>Last scan {relTime(scan.lastFinishedAt, now)}</span>}
      </div>
      {!scan.running && scan.nextRunAt && <span className="text-sm text-muted">next {relTime(scan.nextRunAt, now).replace(" ago", " overdue")}</span>}
      {r && (
        <span className="text-sm text-muted">
          last result: <b className="text-fg">{r.newFindings}</b> new · <b className="text-fg">{r.changedFindings}</b> changed · <b className="text-fg">{r.reportsSent}</b> reports emailed
          {r.error && <span className="ml-2 text-red-300">error: {r.error}</span>}
        </span>
      )}
      <Button className="ml-auto" variant="primary" size="sm" onClick={onScan} loading={busy} disabled={scan.running}>
        <ScanLine className="size-3.5" /> Scan now
      </Button>
    </Card>
  );
}

function Stat({ label, value, tone, sub }: { label: string; value: number | string; tone: string; sub?: React.ReactNode }) {
  return (
    <Card className="px-4 py-3">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">{label}</div>
      <div className={cn("mt-1 text-3xl font-bold tabular-nums", tone)}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </Card>
  );
}

export default function OverviewPage() {
  const now = useNow();
  const status = usePoll<StatusResponse>("/status");
  const findings = usePoll<Finding[]>("/findings");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanErr, setScanErr] = useState<string | null>(null);
  const d = status.data;

  async function scanNow() {
    setScanBusy(true);
    setScanErr(null);
    try {
      await api("/scan", { method: "POST" });
      await status.refresh();
    } catch (e) {
      setScanErr(e instanceof Error ? e.message : String(e));
    } finally {
      setScanBusy(false);
    }
  }

  const groups = groupByCve(findings.data ?? []).filter((g) => g.findings.some((f) => f.status !== "not_affected" || f.naiveVerdict === "vulnerable"));
  const hostName = (id: string) => d?.hosts.find((h) => h.id === id)?.name ?? id;
  const exposedFindings = (findings.data ?? []).filter((f) => f.status === "exposed");
  const exposedHosts = [...new Set(exposedFindings.map((f) => f.hostId))];
  const naiveTotal = d?.hosts.reduce((s, h) => s + h.rawMatchCount, 0) ?? 0;
  const naiveHosts = d?.hosts.filter((h) => h.rawMatchCount > 0).length ?? 0;

  return (
    <>
      <PageHeader
        title="Overview"
        sub="Live inventory and real exposure across your servers"
        right={<LiveTag updatedAt={status.updatedAt} error={status.error} now={now} />}
      />
      <ErrorBanner error={status.error && `Cannot reach Sentinel: ${status.error}`} />
      {status.data?.demo.warning && (
        <div className="mb-4 rounded-xl border border-amber-500/50 bg-amber-950/30 px-4 py-3 text-sm text-amber-100">
          <b>Demo check:</b> {status.data.demo.warning} <a href="/settings" className="underline">Open demo panel</a>
        </div>
      )}
      <ErrorBanner error={scanErr} />

      {!d ? (
        <div className="space-y-4">
          <Skeleton className="h-12" />
          <div className="grid grid-cols-3 gap-4"><Skeleton className="h-64" /><Skeleton className="h-64" /><Skeleton className="h-64" /></div>
        </div>
      ) : (
        <>
          <ScanStrip scan={d.scan} onScan={scanNow} busy={scanBusy} now={now} />

          {exposedHosts.length > 0 ? (
            <div className="mb-5 flex flex-wrap items-center gap-3 rounded-xl border border-red-500/50 bg-gradient-to-r from-red-950/80 to-red-950/20 px-5 py-4">
              <AlertOctagon className="size-7 shrink-0 text-red-400" />
              <div className="min-w-0 flex-1">
                <div className="text-lg font-semibold text-white">
                  {exposedHosts.length === 1 ? "1 server needs emergency action: " : `${exposedHosts.length} servers need emergency action: `}
                  <span className="text-red-300">{exposedHosts.map(hostName).join(", ")}</span>
                </div>
                <div className="text-sm text-red-100/80">
                  {[...new Set(exposedFindings.map((f) => f.cveId))].join(", ")} · a version-number scanner would flag {naiveHosts} server{naiveHosts === 1 ? "" : "s"} — Sentinel checked the actual builds and network exposure.
                </div>
              </div>
              {exposedFindings.some((f) => f.inKev) && <KevBadge className="text-xs" />}
              <Link href={`/findings/${exposedFindings[0]!.id}`}><Button variant="danger">View finding</Button></Link>
            </div>
          ) : (
            <div className="mb-5 flex items-center gap-3 rounded-xl border border-emerald-500/30 bg-emerald-950/30 px-5 py-3.5">
              <ShieldCheck className="size-6 text-emerald-400" />
              <div className="text-sm">
                <span className="font-semibold text-white">No server is currently exposed.</span>{" "}
                <span className="text-muted">Sentinel re-checks every scan and watches new CVEs from CISA KEV and OSV.</span>
              </div>
            </div>
          )}

          <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Exposed" value={d.totals.exposed} tone={d.totals.exposed ? "text-red-400" : "text-dim"} sub="act now" />
            <Stat label="Vulnerable, not exposed" value={d.totals.vulnerable_not_exposed} tone={d.totals.vulnerable_not_exposed ? "text-amber-400" : "text-dim"} sub="upgrade, normal priority" />
            <Stat label="Not affected" value={d.totals.not_affected} tone="text-emerald-400" sub="checked and safe" />
            <Stat label="Exposed on KEV" value={d.inKevExposed} tone={d.inKevExposed ? "text-red-400" : "text-dim"} sub="exploited in the wild" />
            <Stat label="Pending approvals" value={d.pendingActions} tone={d.pendingActions ? "text-amber-300" : "text-dim"} sub={<Link className="hover:underline" href="/approvals">review →</Link>} />
            <Stat label="Naive scanner alerts" value={naiveTotal} tone="text-slate-300" sub={`raw version matches on ${naiveHosts} hosts`} />
          </div>

          <div className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {d.hosts.map((h) => <HostCard key={h.id} host={h} now={now} />)}
            {d.hosts.length === 0 && <Empty className="col-span-full">No hosts enrolled yet. Add one in <Link className="text-blue-400 underline" href="/settings">Settings</Link>.</Empty>}
          </div>

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px]">
            <section>
              <div className="mb-2 flex items-center gap-2">
                <ScanLine className="size-4 text-blue-400" />
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted">Version scanner vs Sentinel</h2>
              </div>
              {groups.length === 0 ? (
                <Empty>No vulnerable package matches yet. When a new CVE lands, this table shows what a version-number scanner would say next to Sentinel&apos;s verdict.</Empty>
              ) : (
                <div className="space-y-4">
                  {groups.slice(0, 3).map((g) => <ContrastTable key={g.cveIds.join()} group={g} hosts={d.hosts} />)}
                  {groups.length > 3 && <Link href="/findings" className="text-sm text-blue-400 hover:underline">+{groups.length - 3} more CVE groups in Findings →</Link>}
                </div>
              )}
            </section>
            <Card className="h-fit">
              <CardHeader title="Recent activity" icon={<Activity className="size-4 text-blue-400" />} right={<Link href="/events" className="text-xs text-blue-400 hover:underline">event log</Link>} />
              <div className="max-h-[560px] overflow-y-auto">
                <ActivityFeed events={d.recentEvents} now={now} />
              </div>
            </Card>
          </div>
        </>
      )}
    </>
  );
}
