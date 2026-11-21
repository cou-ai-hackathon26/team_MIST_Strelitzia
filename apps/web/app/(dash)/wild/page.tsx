"use client";

import Link from "next/link";
import type { HostSummary, WildCve } from "@prohori/shared";
import { CalendarClock, Globe, Skull, Target } from "lucide-react";
import { Badge, Card, Empty, ErrorBanner, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { cn, fmtDay } from "@/lib/utils";

export default function WildPage() {
  const now = useNow();
  const wild = usePoll<WildCve[]>("/wild", 30000);
  const hosts = usePoll<HostSummary[]>("/hosts", 30000);
  const hostName = (id: string) => hosts.data?.find((h) => h.id === id)?.name ?? id;
  const list = [...(wild.data ?? [])].sort((a, b) => (b.affectsHosts.length ? 1 : 0) - (a.affectsHosts.length ? 1 : 0));

  return (
    <>
      <PageHeader
        title="Threat Intelligence"
        icon={<Globe className="size-6 text-blue-400" />}
        sub="Recently added to CISA's Known Exploited Vulnerabilities catalog, correlated against your assets"
        right={<LiveTag updatedAt={wild.updatedAt} error={wild.error} now={now} />}
      />
      <ErrorBanner error={wild.error} />
      {!wild.data ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-48" />)}</div>
      ) : list.length === 0 ? (
        <Empty>No KEV data available.</Empty>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {list.map((c) => {
            const hit = c.affectsHosts.length > 0;
            return (
              <Card key={c.cveId} className={cn("flex flex-col p-4", hit && "border-red-500/60 bg-red-950/20")}>
                {hit && (
                  <div className="-mx-4 -mt-4 mb-3 flex flex-wrap items-center gap-2 rounded-t-xl bg-red-600 px-4 py-1.5 text-xs font-bold text-white">
                    <Target className="size-3.5" /> Affected assets:
                    {c.affectsHosts.map((h) => <Link key={h} href={`/hosts/${h}`} className="rounded bg-white/15 px-1.5 hover:bg-white/25">{hostName(h)}</Link>)}
                  </div>
                )}
                <div className="flex items-start justify-between gap-2">
                  <a href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noreferrer" className="font-mono text-sm font-semibold text-white hover:underline">{c.cveId}</a>
                  {c.knownRansomwareCampaignUse === "Known" && <Badge tone="red"><Skull className="size-3" /> Ransomware: Known</Badge>}
                </div>
                <div className="mt-1 text-xs text-muted">{c.vendorProject} · {c.product}</div>
                <div className="mt-2 font-medium leading-snug text-fg">{c.name}</div>
                <p className="mt-1.5 line-clamp-4 text-xs leading-relaxed text-muted">{c.shortDescription}</p>
                <div className="mt-auto flex items-center gap-3 pt-3 text-[11px] text-dim">
                  <span>Added {fmtDay(c.dateAdded)}</span>
                  <span className="inline-flex items-center gap-1"><CalendarClock className="size-3" /> Due {fmtDay(c.dueDate)}</span>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </>
  );
}
