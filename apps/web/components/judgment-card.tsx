"use client";

import Link from "next/link";
import { useState } from "react";
import type { AdvisoryJudgment, FindingStatus } from "@prohori/shared";
import { ArrowRight, CheckCircle2, CircleAlert, ExternalLink, ListPlus, Loader2, Scale } from "lucide-react";
import { Badge, Button, Input, STATUS_META, Skeleton } from "@/components/ui";
import { ApiError, api, refreshAllPolls, usePoll } from "@/lib/api";
import { JUDGMENT_STATE_META, type JudgmentRef, contrastLine, isJudgmentRunning, judgmentTitle, noProposalReason, verdictCounts } from "@/lib/judgments";
import { actorLabel } from "@/lib/format";
import { cn, fmtDate } from "@/lib/utils";

/** Polls GET /api/judgments/:id every 3 s while the judgment runs, every 15 s once done/failed. */
export function useJudgment(id: string | null) {
  const [running, setRunning] = useState(true);
  const poll = usePoll<AdvisoryJudgment>(id ? `/judgments/${encodeURIComponent(id)}` : null, running ? 3000 : 15000);
  const j = poll.data && poll.data.id === id ? poll.data : undefined;
  const nowRunning = isJudgmentRunning(j);
  if (j && nowRunning !== running) setRunning(nowRunning);
  return { judgment: j, error: poll.error, refresh: poll.refresh };
}

export function JudgmentStateBadge({ j, className }: { j: Pick<AdvisoryJudgment, "state">; className?: string }) {
  const m = JUDGMENT_STATE_META[j.state] ?? { label: j.state, tone: "gray" as const };
  return (
    <Badge tone={m.tone} className={cn("uppercase", className)}>
      {isJudgmentRunning(j) ? <Loader2 className="size-3 animate-spin" /> : j.state === "done" ? <CheckCircle2 className="size-3" /> : <CircleAlert className="size-3" />}
      {m.label}
    </Badge>
  );
}

const ORDER: FindingStatus[] = ["exposed", "vulnerable_not_exposed", "not_affected"];

/** "● 0 Exposed  ● 4 Vulnerable · Unreachable  ● 0 Not Affected" */
export function VerdictCounts({ j, className }: { j: AdvisoryJudgment; className?: string }) {
  const c = verdictCounts(j.hosts);
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-x-3 gap-y-1 text-xs", className)}>
      {ORDER.map((s) => (
        <span key={s} className={cn("inline-flex items-center gap-1.5", c[s] ? STATUS_META[s].text : "text-dim")}>
          <span className={cn("size-1.5 rounded-full", STATUS_META[s].dot, !c[s] && "opacity-40")} />
          <b className="tabular-nums">{c[s]}</b> {STATUS_META[s].label}
        </span>
      ))}
    </span>
  );
}

/** "Track as Findings" button + its outcome; shared by the judgment page and the chat card. */
export function TrackPanel({ j, onTracked, compact }: { j: AdvisoryJudgment; onTracked?: () => void; compact?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [needsCve, setNeedsCve] = useState(false);
  const [cve, setCve] = useState("");
  const done = j.state === "done";
  const noCve = !j.advisory?.cveId;
  const showCveInput = done && (noCve || needsCve);
  const cveOk = /^CVE-\d{4}-\d{4,}$/i.test(cve.trim());

  async function track() {
    setBusy(true);
    setErr(null);
    try {
      const body = cve.trim() ? { cveId: cve.trim().toUpperCase() } : {};
      await api<AdvisoryJudgment>(`/judgments/${encodeURIComponent(j.id)}/track`, { method: "POST", json: body });
      setNeedsCve(false);
      onTracked?.();
      refreshAllPolls();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErr(msg);
      if (e instanceof ApiError && e.status === 409 && (noCve || /cve/i.test(msg))) setNeedsCve(true);
    } finally {
      setBusy(false);
    }
  }

  if (j.tracked) {
    const t = j.tracked;
    const n = t.findingIds.length;
    return (
      <div className={cn("rounded-lg border border-emerald-500/40 bg-emerald-950/20 px-3 py-2.5 text-sm", compact && "text-xs")}>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-emerald-200">
          <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />
          <span>
            Tracked by <b className="font-semibold text-white">{actorLabel(t.by)}</b> at {fmtDate(t.at)} as <span className="font-mono">{t.cveId}</span>: {n} {n === 1 ? "finding" : "findings"}, {t.proposedActions} proposed {t.proposedActions === 1 ? "fix" : "fixes"}
          </span>
        </div>
        {n > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {t.findingIds.map((fid) => {
              const host = j.hosts.find((h) => fid === `f_${h.hostId}_${t.cveId}`);
              return (
                <Link key={fid} href={`/findings/${encodeURIComponent(fid)}`} className="inline-flex items-center gap-1 rounded border border-line bg-bg px-1.5 py-0.5 text-[11px] text-blue-300 hover:underline">
                  {host ? host.hostName : <span className="font-mono">{fid}</span>} <ArrowRight className="size-3" />
                </Link>
              );
            })}
          </div>
        )}
        {t.proposedActions > 0 ? (
          <div className="mt-2 text-xs text-muted">
            Proposed fixes await your approval in <Link href="/approvals" className="text-blue-400 hover:underline">Approvals</Link>.
          </div>
        ) : (
          <div className="mt-2 text-xs text-muted">{noProposalReason(j)}</div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {showCveInput && (
        <div className="space-y-1">
          <label className="block text-xs text-muted">
            {noCve ? "This advisory has no CVE id. Enter one to track it as findings:" : "Enter the CVE id to track this advisory under:"}
          </label>
          <Input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2026-12345" className={cn("font-mono", compact && "h-8 text-xs")} />
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="primary"
          size={compact ? "sm" : "md"}
          loading={busy}
          disabled={!done || (showCveInput && !cveOk)}
          onClick={() => void track()}
          title={done ? "Write findings for every matched asset and propose fixes under the normal approval rules" : "Available once the judgment is complete"}
        >
          <ListPlus className="size-4" /> Track as Findings
        </Button>
        {!done && <span className="text-xs text-dim">{j.state === "failed" ? "The judgment failed; nothing to track." : "Available once the judgment is complete"}</span>}
      </div>
      {err && <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-xs text-red-200">{err}</div>}
    </div>
  );
}

/** Compact live judgment card used in Sentinel chat (judgeAdvisory / getJudgment tool parts). */
export function JudgmentCard({ initial }: { initial: JudgmentRef }) {
  const { judgment: j, error, refresh } = useJudgment(initial.id);
  const href = `/judgments/${encodeURIComponent(initial.id)}`;

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-panel">
      <div className="flex items-center gap-2 border-b border-line bg-panel-2/60 px-4 py-2.5">
        <Scale className="size-4 shrink-0 text-blue-400" />
        <span className="font-display text-sm text-fg">Advisory Judgment</span>
        <span className="font-mono text-[11px] text-dim">{initial.id}</span>
        <span className="ml-auto">{j && <JudgmentStateBadge j={j} />}</span>
      </div>
      {!j ? (
        error ? (
          <div className="px-4 py-3 text-sm text-red-200">Unable to load judgment: {error}</div>
        ) : (
          <div className="p-4"><Skeleton className="h-16" /></div>
        )
      ) : (
        <div className="space-y-3 px-4 py-3">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-white">{judgmentTitle(j)}</span>
              <span className="font-mono text-xs text-muted">{j.advisory?.cveId ?? (j.advisory ? "no CVE id" : "")}</span>
            </div>
            <a href={j.url} target="_blank" rel="noreferrer" className="mt-0.5 inline-flex max-w-full items-center gap-1 truncate font-mono text-[11px] text-blue-300 hover:underline">
              <span className="truncate">{j.url.replace(/^https?:\/\//, "")}</span> <ExternalLink className="size-3 shrink-0" />
            </a>
          </div>
          {isJudgmentRunning(j) && (
            <div className="flex items-center gap-2 text-xs text-blue-200"><Loader2 className="size-3.5 animate-spin" /> {j.progress || "Working…"}</div>
          )}
          {j.state === "failed" && j.error && <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-xs text-red-200">{j.error}</div>}
          {j.hosts.length > 0 && <VerdictCounts j={j} />}
          {j.state === "done" && contrastLine(j) && <p className="text-sm text-fg">{contrastLine(j)}</p>}
          {j.state === "done" && j.hosts.length === 0 && (
            <p className="text-sm text-muted">The affected package is not installed on any asset.</p>
          )}
          <div className="flex flex-wrap items-end justify-between gap-3">
            {j.state === "done" ? <div className="min-w-0 flex-1"><TrackPanel j={j} onTracked={() => void refresh()} compact /></div> : <span />}
            <Link href={href} className="inline-flex items-center gap-1 text-xs font-medium text-blue-400 hover:underline">
              Open Judgment <ArrowRight className="size-3.5" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
