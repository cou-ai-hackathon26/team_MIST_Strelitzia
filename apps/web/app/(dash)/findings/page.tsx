"use client";

import Link from "next/link";
import { useState } from "react";
import type { Finding, FindingStatus, HostSummary } from "@prohori/shared";
import { ArrowRight, Bug, HelpCircle } from "lucide-react";
import { FlashOnChange } from "@/components/flash";
import { Card, Empty, ErrorBanner, KevBadge, LiveTag, PageHeader, PriorityBadge, STATUS_META, Skeleton, StatusPill } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { sortFindings, versionBanner } from "@/lib/format";
import { cn, relTime } from "@/lib/utils";

const FILTERS: (FindingStatus | "all")[] = ["all", "exposed", "vulnerable_not_exposed", "not_affected"];

export default function FindingsPage() {
  const now = useNow();
  const findings = usePoll<Finding[]>("/findings");
  const hosts = usePoll<HostSummary[]>("/hosts", 10000);
  const [status, setStatus] = useState<FindingStatus | "all">("all");
  const [host, setHost] = useState<string>("all");
  const all = [...(findings.data ?? [])].sort(sortFindings);
  const rows = all.filter((f) => (status === "all" || f.status === status) && (host === "all" || f.hostId === host));
  const hostName = (id: string) => hosts.data?.find((h) => h.id === id)?.name ?? id;

  return (
    <>
      <PageHeader title="Findings" icon={<Bug className="size-6 text-blue-400" />} sub="Every (server, CVE) pair Sentinel evaluated, sorted by priority" right={<LiveTag updatedAt={findings.updatedAt} error={findings.error} now={now} />} />
      <ErrorBanner error={findings.error} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {FILTERS.map((s) => {
          const n = s === "all" ? all.length : all.filter((f) => f.status === s).length;
          return (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium",
                status === s ? "border-blue-500/60 bg-blue-500/15 text-white" : "border-line bg-panel text-muted hover:text-fg",
              )}
            >
              {s !== "all" && <span className={cn("size-1.5 rounded-full", STATUS_META[s].dot)} />}
              {s === "all" ? "All" : STATUS_META[s].label} <span className="text-dim">{n}</span>
            </button>
          );
        })}
        <select value={host} onChange={(e) => setHost(e.target.value)} className="ml-auto h-8 rounded-lg border border-line bg-panel px-2 text-xs text-fg">
          <option value="all">All hosts</option>
          {hosts.data?.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
        </select>
      </div>

      {!findings.data ? (
        <Skeleton className="h-64" />
      ) : rows.length === 0 ? (
        <Empty>No findings{status !== "all" || host !== "all" ? " match these filters" : " yet — the next scan will populate this list"}.</Empty>
      ) : (
        <Card className="overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-panel-2/60 text-left text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2.5 font-semibold">Priority</th>
                <th className="px-4 py-2.5 font-semibold">Verdict</th>
                <th className="px-4 py-2.5 font-semibold">CVE</th>
                <th className="px-4 py-2.5 font-semibold">Host</th>
                <th className="px-4 py-2.5 font-semibold">Package: installed → fixed</th>
                <th className="px-4 py-2.5 font-semibold">Naive</th>
                <th className="px-4 py-2.5 font-semibold">Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.id} className={cn("group border-t border-line/70 hover:bg-panel-2/60", f.status === "exposed" && "bg-red-500/[0.05]")}>
                  <td className="px-4 py-2.5"><PriorityBadge priority={f.priority} /></td>
                  <td className="px-4 py-2.5">
                    <FlashOnChange value={f.status}><StatusPill status={f.status} /></FlashOnChange>
                    {f.needsConfirmation && <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-300"><HelpCircle className="size-3" /> needs confirmation</div>}
                  </td>
                  <td className="px-4 py-2.5">
                    <Link href={`/findings/${f.id}`} className="font-mono font-semibold text-white hover:underline">{f.cveId}</Link>
                    {f.inKev && <KevBadge className="ml-2" />}
                    <div className="max-w-xs truncate text-xs text-muted">{f.title}</div>
                  </td>
                  <td className="px-4 py-2.5">
                    <Link href={`/hosts/${f.hostId}`} className="hover:underline">{hostName(f.hostId)}</Link>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">
                    {f.package ? (
                      <>
                        <span className="text-muted">{f.package.name}</span>{" "}
                        <span className={f.status === "not_affected" ? "text-emerald-300" : "text-red-300"}>{f.package.installedVersion}</span>
                        <span className="text-dim"> → </span>
                        <span className="text-emerald-300">{f.package.fixedVersion ?? "no fix yet"}</span>
                        <div className="font-sans text-[11px] text-dim">banner: {versionBanner(f.package)}</div>
                      </>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    <span className={f.naiveVerdict === "vulnerable" ? "text-red-300" : "text-muted"}>{f.naiveVerdict.replace("_", " ")}</span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted">{relTime(f.updatedAt, now)}</td>
                  <td className="px-2"><Link href={`/findings/${f.id}`}><ArrowRight className="size-4 text-dim group-hover:text-fg" /></Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </>
  );
}
