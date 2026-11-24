"use client";

import Link from "next/link";
import { use } from "react";
import type { Report } from "@prohori/shared";
import { ArrowLeft, ExternalLink, Mail } from "lucide-react";
import { Markdown } from "@/components/markdown";
import { Badge, Card, ErrorBanner, Skeleton } from "@/components/ui";
import { usePoll } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

export default function ReportDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: r, error } = usePoll<Report>(`/reports/${encodeURIComponent(id)}`, 0);
  return (
    <>
      <Link href="/reports" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-fg"><ArrowLeft className="size-4" /> Reports</Link>
      <ErrorBanner error={error} />
      {!r ? (
        <Skeleton className="h-96" />
      ) : (
        <div className="mx-auto max-w-4xl">
          <div className="mb-4">
            <h1 className="font-display text-2xl text-white">{r.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted">
              <span>{fmtDate(r.createdAt)}</span>
              {r.emailedTo.length > 0 ? (
                <Badge tone="blue"><Mail className="size-3" /> Sent to {r.emailedTo.join(", ")}{r.emailedAt ? ` · ${fmtDate(r.emailedAt)}` : ""}</Badge>
              ) : (
                <Badge tone="gray">Not sent</Badge>
              )}
              <a href="http://127.0.0.1:8025" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline">Open mailbox <ExternalLink className="size-3" /></a>
            </div>
            {r.findingIds.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
                {r.findingIds.map((fid) => <Link key={fid} href={`/findings/${fid}`} className="rounded border border-line px-1.5 py-0.5 font-mono text-muted hover:text-fg">{fid}</Link>)}
              </div>
            )}
          </div>
          <Card className="p-6"><Markdown>{r.markdown}</Markdown></Card>
        </div>
      )}
    </>
  );
}
