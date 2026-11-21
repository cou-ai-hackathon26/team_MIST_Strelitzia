"use client";

import Link from "next/link";
import type { Finding, HostSummary, Report } from "@prohori/shared";
import { FileText, Mail } from "lucide-react";
import { Badge, Card, Empty, ErrorBanner, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { fmtDate, relTime } from "@/lib/utils";

export default function ReportsPage() {
  const now = useNow();
  const { data, error, updatedAt } = usePoll<Report[]>("/reports", 5000);
  const findings = usePoll<Finding[]>("/findings", 10000);
  const hosts = usePoll<HostSummary[]>("/hosts", 30000);
  const affected = (r: Report) => {
    const ids = new Set(r.findingIds.map((fid) => findings.data?.find((f) => f.id === fid)).filter((f) => f && f.status !== "not_affected").map((f) => f!.hostId));
    return [...ids].map((id) => hosts.data?.find((h) => h.id === id)?.name ?? id);
  };
  return (
    <>
      <PageHeader title="Reports" icon={<FileText className="size-6 text-blue-400" />} sub="Incident reports issued by Sentinel and delivered to your security team" right={<LiveTag updatedAt={updatedAt} error={error} now={now} />} />
      <ErrorBanner error={error} />
      {!data ? (
        <Skeleton className="h-48" />
      ) : data.length === 0 ? (
        <Empty>No reports issued. Sentinel issues a report whenever a scan detects a new or changed finding.</Empty>
      ) : (
        <div className="space-y-3">
          {data.map((r) => (
            <Link key={r.id} href={`/reports/${r.id}`} className="block">
              <Card className="flex items-center gap-4 px-4 py-3 transition-colors hover:border-line-2 hover:bg-panel-2/60">
                <FileText className="size-5 shrink-0 text-blue-400" />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-white">{r.title}</div>
                  <div className="text-xs text-muted">{fmtDate(r.createdAt)} · {relTime(r.createdAt, now)} · {r.findingIds.length} finding{r.findingIds.length === 1 ? "" : "s"}</div>
                  {affected(r).length > 0 && (
                    <div className="mt-1 flex flex-wrap items-center gap-1 text-xs"><span className="text-dim">Affected:</span>{affected(r).map((n) => <Badge key={n} tone="amber">{n}</Badge>)}</div>
                  )}
                </div>
                {r.emailedTo.length > 0 ? (
                  <Badge tone="blue"><Mail className="size-3" /> Sent to {r.emailedTo.join(", ")}{r.emailedAt ? ` at ${fmtDate(r.emailedAt)}` : ""}</Badge>
                ) : (
                  <Badge tone="gray">Not sent</Badge>
                )}
              </Card>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
