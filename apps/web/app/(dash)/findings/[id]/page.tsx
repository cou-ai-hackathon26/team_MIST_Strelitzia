"use client";

import Link from "next/link";
import { use } from "react";
import type { Finding, HostSummary } from "@prohori/shared";
import { ArrowLeft, FileText, HelpCircle, ListChecks, Microscope, ScanLine } from "lucide-react";
import { FlashOnChange } from "@/components/flash";
import { ContrastTable } from "@/components/contrast";
import { Markdown } from "@/components/markdown";
import { Badge, Card, CardHeader, ErrorBanner, KV, KevBadge, PriorityBadge, Skeleton, StatusPill } from "@/components/ui";
import { usePoll } from "@/lib/api";
import { groupByCve, shortVerdictReason, versionBanner } from "@/lib/format";
import { fmtDate } from "@/lib/utils";
import { HostFixProgress } from "@/components/fix-progress";

function isPartial(m: string, i: number): boolean {
  if (/\bpartial\b|incomplete|interim|temporar|reduces?|does not fully/i.test(m)) return true;
  return i > 0;
}

export default function FindingDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: f, error } = usePoll<Finding>(`/findings/${encodeURIComponent(id)}`, 5000);
  const hosts = usePoll<HostSummary[]>("/hosts", 15000);
  const all = usePoll<Finding[]>(f ? `/findings` : null, 10000);
  const hostName = (hid: string) => hosts.data?.find((h) => h.id === hid)?.name ?? hid;
  const siblings = groupByCve((all.data ?? []).filter((x) => x.cveId === f?.cveId));

  return (
    <>
      <Link href="/findings" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-fg"><ArrowLeft className="size-4" /> Findings</Link>
      <ErrorBanner error={error} />
      {!f ? (
        <Skeleton className="h-96" />
      ) : (
        <>
          <div className="mb-5 rounded-xl border border-line bg-panel p-5">
            <div className="flex flex-wrap items-center gap-2">
              <FlashOnChange value={f.status}><StatusPill status={f.status} size="lg" /></FlashOnChange>
              <PriorityBadge priority={f.priority} />
              {f.inKev && <KevBadge />}
              {f.needsConfirmation && <Badge tone="amber"><HelpCircle className="size-3" /> needs confirmation</Badge>}
              <Badge tone="gray">confidence: {f.confidence}</Badge>
              {f.cvss && <Badge tone="gray" className="font-mono">CVSS {f.cvss}</Badge>}
            </div>
            <h1 className="mt-3 text-2xl font-semibold text-white">
              <span className="font-mono">{f.cveId}</span> on <Link href={`/hosts/${f.hostId}`} className="hover:underline">{hostName(f.hostId)}</Link>
            </h1>
            <p className="mt-1 text-muted">{f.title}</p>
            {f.aliases.length > 0 && <p className="mt-1 font-mono text-xs text-dim">aliases: {f.aliases.join(", ")}</p>}
            <p className="mt-3 text-sm text-fg">{shortVerdictReason(f)}</p>
            <HostFixProgress hostId={f.hostId} hostName={hostName(f.hostId)} className="mt-3" />
          </div>

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
            <div className="space-y-5">
              <Card>
                <CardHeader title="Naive scanner vs Sentinel" icon={<ScanLine className="size-4 text-blue-400" />} />
                <div className="grid grid-cols-2 divide-x divide-line">
                  <div className="p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Version-number scanner</div>
                    <div className="mt-2 text-lg font-semibold">{versionBanner(f.package)}</div>
                    <div className={f.naiveVerdict === "vulnerable" ? "mt-1 text-xl font-bold text-red-400" : "mt-1 text-xl font-bold text-muted"}>
                      {f.naiveVerdict === "vulnerable" ? "VULNERABLE" : f.naiveVerdict === "not_vulnerable" ? "NOT VULNERABLE" : "UNKNOWN"}
                    </div>
                    <div className="mt-1 text-xs text-muted">compares the upstream version number only</div>
                  </div>
                  <div className="p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Sentinel (distro build + exposure)</div>
                    <div className="mt-2 font-mono text-sm">{f.package?.installedVersion ?? "—"}</div>
                    <div className="mt-1"><StatusPill status={f.status} size="lg" /></div>
                    <div className="mt-1 text-xs text-muted">checks the exact build, distro fixes and network reachability</div>
                  </div>
                </div>
              </Card>

              <Card>
                <CardHeader title="Rationale" icon={<Microscope className="size-4 text-blue-400" />} sub="Evidence-based explanation written by the agent" />
                <div className="p-5"><Markdown>{f.rationale || "_No rationale recorded._"}</Markdown></div>
              </Card>

              {siblings.length > 0 && siblings[0]!.findings.length > 1 && (
                <div>
                  <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted">Same CVE on other servers</h2>
                  <ContrastTable group={siblings[0]!} hosts={hosts.data} />
                </div>
              )}
            </div>

            <div className="space-y-5">
              <Card>
                <CardHeader title="Mitigations" icon={<ListChecks className="size-4 text-blue-400" />} sub="First item is the complete fix when one exists" />
                <ol className="space-y-2 p-4">
                  {f.mitigations.length === 0 && <li className="text-sm text-muted">None needed.</li>}
                  {f.mitigations.map((m, i) => {
                    const partial = isPartial(m, i);
                    return (
                      <li key={i} className={partial ? "rounded-lg border border-line p-3" : "rounded-lg border border-emerald-500/40 bg-emerald-950/30 p-3"}>
                        <div className="mb-1">
                          {partial ? <Badge tone="amber">PARTIAL · interim only</Badge> : <Badge tone="green">COMPLETE FIX</Badge>}
                        </div>
                        <Markdown className="text-sm">{m}</Markdown>
                      </li>
                    );
                  })}
                </ol>
              </Card>

              <Card>
                <CardHeader title="Evidence" icon={<Microscope className="size-4 text-blue-400" />} sub="Collected live from the host via osquery" />
                <div className="px-4 py-2">
                  {f.package && (
                    <>
                      <KV k="package" v={f.package.name} />
                      <KV k="installed" v={f.package.installedVersion} />
                      <KV k="fixed in" v={f.package.fixedVersion ?? "no fixed version"} />
                    </>
                  )}
                  {Object.entries(f.evidence).map(([k, v]) => <KV key={k} k={k} v={v} />)}
                </div>
              </Card>

              <Card className="p-4 text-sm">
                <KV k="first seen" v={fmtDate(f.firstSeen)} mono={false} />
                <KV k="updated" v={fmtDate(f.updatedAt)} mono={false} />
                <KV
                  k="report"
                  mono={false}
                  v={f.reportId ? <Link href={`/reports/${f.reportId}`} className="inline-flex items-center gap-1 text-blue-400 hover:underline"><FileText className="size-3.5" /> open report</Link> : "not reported yet"}
                />
              </Card>
            </div>
          </div>
        </>
      )}
    </>
  );
}
