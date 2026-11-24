"use client";

import Link from "next/link";
import { Fragment, use, useState } from "react";
import type { AdvisoryJudgment, FindingStatus, JudgmentHost } from "@prohori/shared";
import {
  ArrowLeft, ArrowRight, Bot, ChevronDown, ChevronRight, CircleAlert, ExternalLink, FileSearch, HelpCircle, ListPlus,
  Loader2, MessageSquare, Microscope, Scale, ScrollText, Server, ShieldCheck,
} from "lucide-react";
import { FlashOnChange } from "@/components/flash";
import { InvestigationPanel, ThreatProfileSection } from "@/components/investigation";
import { JudgmentStateBadge, TrackPanel, useJudgment } from "@/components/judgment-card";
import { Markdown } from "@/components/markdown";
import { Badge, Card, CardHeader, ErrorBanner, KV, PriorityBadge, STATUS_META, Skeleton, StatusPill } from "@/components/ui";
import { FIX_SOURCE_LABEL, NAIVE_LABEL, contrastLine, isJudgmentRunning, judgmentTitle, verdictCounts } from "@/lib/judgments";
import { STATUS_RANK, actorLabel } from "@/lib/format";
import { cn, fmtDate } from "@/lib/utils";

const ORDER: FindingStatus[] = ["exposed", "vulnerable_not_exposed", "not_affected"];

function ContrastStrip({ j }: { j: AdvisoryJudgment }) {
  const c = verdictCounts(j.hosts);
  return (
    <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,2.4fr)] md:items-stretch">
      <div className="rounded-xl border border-line bg-panel px-4 py-3">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Version-Only Check</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={cn("font-display text-3xl tabular-nums", c.naiveVulnerable ? "text-red-300" : "text-emerald-300")}>{c.naiveVulnerable}</span>
          <span className="text-sm text-muted">vulnerable</span>
        </div>
        <div className="mt-1 text-xs text-dim">Compares version numbers only, of {j.hosts.length} matched {j.hosts.length === 1 ? "asset" : "assets"}</div>
      </div>
      <div className="hidden items-center md:flex"><ArrowRight className="size-5 text-dim" /></div>
      <div className="rounded-xl border border-blue-500/30 bg-panel px-4 py-3">
        <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-blue-300"><Bot className="size-3.5" /> Sentinel</div>
        <div className="mt-1 grid grid-cols-3 gap-3">
          {ORDER.map((s) => (
            <div key={s}>
              <div className={cn("font-display text-3xl tabular-nums", c[s] ? STATUS_META[s].text : "text-dim")}>{c[s]}</div>
              <div className="flex items-center gap-1.5 text-xs text-muted"><span className={cn("size-1.5 rounded-full", STATUS_META[s].dot)} /> {STATUS_META[s].label}</div>
            </div>
          ))}
        </div>
      </div>
      {contrastLine(j) && <p className="text-sm text-fg md:col-span-3">{contrastLine(j)}</p>}
    </div>
  );
}

function Pending({ children }: { children: React.ReactNode }) {
  return <div className="flex items-center gap-2 px-4 py-6 text-sm text-muted"><Loader2 className="size-4 animate-spin text-blue-400" /> {children}</div>;
}

function AdvisoryFacts({ j }: { j: AdvisoryJudgment }) {
  const a = j.advisory;
  if (!a) return isJudgmentRunning(j) ? <Pending>Reading the advisory…</Pending> : <div className="px-4 py-6 text-sm text-muted">No advisory details were extracted.</div>;
  const fixLabel = a.fixAvailable === "yes" ? <Badge tone="green">Fix Available</Badge> : a.fixAvailable === "no" ? <Badge tone="red">No Fix Available</Badge> : <Badge tone="gray">Fix Status Unknown</Badge>;
  return (
    <div className="px-4 py-2">
      <KV k="Product" v={a.product || "—"} mono={false} />
      <KV k="Matched package" v={a.sourcePackageGuess || "—"} />
      <KV
        k="Affected ranges"
        v={
          a.affectedRanges.length === 0 ? "Not stated" : (
            <ul className="space-y-0.5">
              {a.affectedRanges.map((r, i) => (
                <li key={i}>
                  {r.introduced ? `≥ ${r.introduced}` : "all versions"}
                  {r.fixed && <span className="text-emerald-300">{`, < ${r.fixed}`}</span>}
                  {r.lastAffected && <span className="text-red-300">{`, ≤ ${r.lastAffected} (last affected)`}</span>}
                </li>
              ))}
            </ul>
          )
        }
      />
      <KV k="Fixed versions" v={<span className="flex flex-wrap items-center gap-2">{a.fixedVersions.length ? <span className="text-emerald-300">{a.fixedVersions.join(", ")}</span> : <span className="text-muted">None stated</span>}{fixLabel}</span>} />
      <KV
        k="Conditions"
        mono={false}
        v={a.conditions.length ? <ul className="list-disc space-y-0.5 pl-4">{a.conditions.map((c, i) => <li key={i}>{c}</li>)}</ul> : <span className="text-muted">None stated</span>}
      />
      <KV
        k="Distro records"
        v={a.distroRecords.length ? a.distroRecords.join(", ") : <Badge tone="amber"><HelpCircle className="size-3" /> Advisory Only · Needs Confirmation</Badge>}
      />
      {a.otherIds.length > 0 && <KV k="Other ids on the page" v={<span className="text-muted">{a.otherIds.join(", ")}</span>} />}
    </div>
  );
}

function HostDetail({ h, j }: { h: JudgmentHost; j: AdvisoryJudgment }) {
  return (
    <div className="space-y-4 p-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">Rationale</div>
          <Markdown>{h.rationale || "_No rationale recorded._"}</Markdown>
        </div>
        <div className="rounded-lg border border-line bg-bg px-3 py-1">
          <KV k="Reachability" v={h.reachability || "—"} mono={false} />
          <KV k="Exposed ports" v={h.exposedPorts.length ? h.exposedPorts.join(", ") : "None"} />
          <KV k="Binaries" v={h.binaries.length ? h.binaries.join(", ") : "—"} />
          <KV k="Fix status" v={`${FIX_SOURCE_LABEL[h.fixStatus.source]}: ${h.fixStatus.detail}`} mono={false} />
          <KV k="Fixed build" v={h.fixStatus.fixedVersion ?? "No fixed build"} />
          <KV k="Confidence" v={h.confidence} mono={false} />
        </div>
      </div>
      {h.mitigations.length > 0 && (
        <div>
          <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">Mitigations</div>
          <ol className="space-y-1.5">
            {h.mitigations.map((m, i) => <li key={i} className="rounded-lg border border-line px-3 py-2"><Markdown className="text-sm">{m}</Markdown></li>)}
          </ol>
        </div>
      )}
      <InvestigationPanel
        investigation={h.investigation}
        cveId={j.advisory?.cveId ?? null}
        hostName={h.hostName}
        showProfile={false}
        idPrefix={h.hostId}
        emptyText="No investigation recorded for this asset."
        sub="Checks Sentinel ran on this asset with read-only tools, the code guardrails applied, and the remediation plan"
      />
    </div>
  );
}

function HostTable({ j }: { j: AdvisoryJudgment }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const hosts = [...j.hosts].sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || a.hostName.localeCompare(b.hostName));
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-panel-2/60 text-left text-[11px] uppercase tracking-wider text-dim">
          <tr>
            <th className="w-8" />
            <th className="px-3 py-2.5 font-semibold">Asset</th>
            <th className="px-3 py-2.5 font-semibold">Installed Build</th>
            <th className="px-3 py-2.5 font-semibold">Fix Status</th>
            <th className="px-3 py-2.5 font-semibold">Version-Only</th>
            <th className="px-3 py-2.5 font-semibold">Sentinel</th>
            <th className="px-3 py-2.5 font-semibold">Priority</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => {
            const isOpen = !!open[h.hostId];
            const naive = NAIVE_LABEL[h.naiveVerdict];
            return (
              <Fragment key={h.hostId}>
                <tr
                  onClick={() => setOpen((o) => ({ ...o, [h.hostId]: !o[h.hostId] }))}
                  className={cn("cursor-pointer border-t border-line/70 align-top hover:bg-panel-2/60", h.status === "exposed" && "bg-red-500/[0.06]", isOpen && "bg-panel-2/40")}
                >
                  <td className="py-2.5 pl-3">{isOpen ? <ChevronDown className="size-4 text-muted" /> : <ChevronRight className="size-4 text-dim" />}</td>
                  <td className="px-3 py-2.5">
                    <Link href={`/hosts/${h.hostId}`} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap font-semibold text-white hover:underline">{h.hostName}</Link>
                    <div className="font-mono text-[11px] text-dim">{h.hostId}</div>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="font-mono text-xs text-fg">{h.sourcePackage} {h.installedVersion}</div>
                    <div className="text-[11px] text-dim">Upstream {h.upstreamVersion} · {h.packageMatch}</div>
                  </td>
                  <td className="max-w-xs px-3 py-2.5">
                    <Badge tone={h.fixStatus.source === "distro_record" ? "blue" : "amber"}>{FIX_SOURCE_LABEL[h.fixStatus.source]}</Badge>
                    <div className="mt-1 text-[11px] leading-snug text-muted">{h.fixStatus.detail}</div>
                  </td>
                  <td className="px-3 py-2.5"><span className={cn("text-xs font-semibold", naive.cls)}>{naive.label}</span></td>
                  <td className="px-3 py-2.5">
                    <FlashOnChange value={h.status}><StatusPill status={h.status} /></FlashOnChange>
                    {h.needsConfirmation && <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-300"><HelpCircle className="size-3" /> Pending confirmation</div>}
                  </td>
                  <td className="px-3 py-2.5"><PriorityBadge priority={h.priority} /></td>
                </tr>
                {isOpen && (
                  <tr className="border-t border-line/40 bg-bg/40">
                    <td colSpan={7} className="p-0"><HostDetail h={h} j={j} /></td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function JudgmentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { judgment: j, error, refresh } = useJudgment(id);
  const running = isJudgmentRunning(j);

  return (
    <>
      <Link href="/judgments" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-fg"><ArrowLeft className="size-4" /> Advisory Judgments</Link>
      <ErrorBanner error={error} />
      {!j ? (
        error ? null : <Skeleton className="h-96" />
      ) : (
        <>
          <div className="mb-5 rounded-xl border border-line bg-panel p-5">
            <div className="flex flex-wrap items-center gap-2">
              <JudgmentStateBadge j={j} className="px-2 py-1 text-xs" />
              {j.tracked && <Badge tone="green"><ListPlus className="size-3" /> Tracked as Findings</Badge>}
              <span className="ml-auto font-mono text-[11px] text-dim">{j.id}</span>
            </div>
            <h1 className="font-display mt-3 text-2xl text-white">{judgmentTitle(j)}</h1>
            <p className="mt-1 font-mono text-sm text-muted">{j.advisory?.cveId ?? (j.advisory ? "no CVE id" : "CVE id pending")}</p>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
              <a href={j.url} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1 font-mono text-blue-300 hover:underline">
                <span className="truncate">{j.url}</span> <ExternalLink className="size-3 shrink-0" />
              </a>
              <span>Requested by <b className="font-medium text-fg">{actorLabel(j.requestedBy)}</b> at {fmtDate(j.createdAt)}</span>
              {j.focus && <span>Focus: <span className="text-fg">{j.focus}</span></span>}
              {j.threadId && (
                <Link href={`/chat?thread=${encodeURIComponent(j.threadId)}`} className="inline-flex items-center gap-1 text-blue-400 hover:underline"><MessageSquare className="size-3" /> View conversation</Link>
              )}
            </div>
            {running && (
              <div className="mt-3 flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-sm text-blue-100">
                <Loader2 className="size-4 animate-spin text-blue-300" /> {j.progress || "Working…"}
              </div>
            )}
            {j.state === "failed" && (
              <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-sm text-red-200">
                <CircleAlert className="mt-0.5 size-4 shrink-0" /> {j.error || "The judgment failed."}
              </div>
            )}
          </div>

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
            <div className="min-w-0 space-y-5">
              <Card>
                <CardHeader title="Verdict" icon={<Microscope className="size-4 text-blue-400" />} sub="Sentinel's summary across every matched asset" />
                {j.summary ? <div className="p-5"><Markdown>{j.summary}</Markdown></div> : running ? <Pending>Sentinel is still working on this advisory…</Pending> : <div className="px-5 py-6 text-sm text-muted">No summary recorded.</div>}
              </Card>

              {j.hosts.length > 0 && <ContrastStrip j={j} />}

              <Card className="overflow-hidden">
                <CardHeader
                  title="Assets With the Affected Package"
                  icon={<Server className="size-4 text-blue-400" />}
                  sub="Click a row for Sentinel's rationale and investigation on that asset"
                />
                {j.hosts.length > 0 ? (
                  <HostTable j={j} />
                ) : running ? (
                  <Pending>Matching the advisory to installed packages…</Pending>
                ) : (
                  <div className="flex items-center gap-2 px-4 py-6 text-sm text-muted"><ShieldCheck className="size-4 text-emerald-400" /> The affected package is not installed on any asset.</div>
                )}
                {j.notInstalledOn.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 border-t border-line px-4 py-3 text-xs">
                    <span className="text-dim">Not installed on:</span>
                    {j.notInstalledOn.map((h) => (
                      <Link key={h.hostId} href={`/hosts/${h.hostId}`} className="rounded border border-line bg-bg px-1.5 py-0.5 text-muted hover:text-fg">{h.hostName}</Link>
                    ))}
                  </div>
                )}
              </Card>
            </div>

            <div className="space-y-5">
              <Card>
                <CardHeader title="Track as Findings" icon={<ListPlus className="size-4 text-blue-400" />} sub="Writes a finding per matched asset and proposes fixes under the normal approval rules" />
                <div className="p-4"><TrackPanel j={j} onTracked={() => void refresh()} /></div>
              </Card>

              <Card>
                <CardHeader title="Advisory Facts" icon={<FileSearch className="size-4 text-blue-400" />} sub="Extracted from the advisory page" />
                <AdvisoryFacts j={j} />
              </Card>

              <Card>
                <CardHeader title="Threat Profile" icon={<ScrollText className="size-4 text-blue-400" />} sub="Derived from the advisory" />
                <div className="p-4">
                  {j.profile ? <ThreatProfileSection profile={j.profile} /> : running ? <div className="flex items-center gap-2 text-sm text-muted"><Loader2 className="size-4 animate-spin text-blue-400" /> Analysing the advisory…</div> : <p className="text-sm text-muted">No threat profile recorded.</p>}
                  {j.profile && j.profile.preconditions.length > 0 && (
                    <div className="mt-3">
                      <div className="mb-1.5 text-xs font-medium text-muted">Preconditions</div>
                      <ul className="space-y-1.5">
                        {j.profile.preconditions.map((pc) => (
                          <li key={pc.id} className="rounded-lg border border-line px-3 py-2 text-sm">
                            <div className="text-fg">{pc.text}</div>
                            {pc.howToCheck && <div className="mt-0.5 text-xs text-muted"><span className="text-dim">How to check:</span> {pc.howToCheck}</div>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </Card>

              <div className="flex items-center gap-1.5 px-1 text-[11px] text-dim"><Scale className="size-3" /> Updated {fmtDate(j.updatedAt)}</div>
            </div>
          </div>
        </>
      )}
    </>
  );
}
