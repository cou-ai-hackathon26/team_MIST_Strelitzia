"use client";

import Link from "next/link";
import { useState } from "react";
import type { AuditEvent, HostSummary } from "@prohori/shared";
import { Bug, MessageSquare, ScrollText } from "lucide-react";
import { ActorChip, EVENT_ICON, eventThreadId } from "@/components/activity";
import { Card, Empty, ErrorBanner, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { EVENT_TONE } from "@/lib/format";
import { cn, fmtDate, relTime } from "@/lib/utils";

const KIND_GROUPS: { label: string; kinds: AuditEvent["kind"][] }[] = [
  { label: "Vulnerabilities", kinds: ["cve_discovered", "vulnerable_detected", "finding_new", "finding_changed"] },
  { label: "Reports", kinds: ["report_generated", "report_sent"] },
  { label: "Actions", kinds: ["action_proposed", "action_revised", "action_approved", "action_rejected", "action_applied", "action_failed", "action_rolled_back"] },
  { label: "Advisory Judgments", kinds: ["judgment_requested", "judgment_done", "judgment_tracked"] },
  { label: "Scans", kinds: ["scan_started", "scan_finished", "wild_refreshed"] },
  { label: "Assets", kinds: ["host_online", "host_offline", "inventory_changed"] },
  { label: "Administration", kinds: ["login", "settings_changed", "demo_inject", "error"] },
];

function str(v: unknown): string | null {
  if (typeof v === "string" && v) return v;
  if (Array.isArray(v) && v.length) return v.join(", ");
  return null;
}

/** Extra human-readable details pulled from event.data. */
function Details({ e }: { e: AuditEvent }) {
  const d = e.data ?? {};
  const note = str(d.note) ?? str(d.decisionNote);
  const recipients = str(d.recipients) ?? str(d.emailedTo) ?? str(d.to);
  const thread = eventThreadId(e);
  const reportId = str(d.reportId);
  const actionId = str(d.actionId);
  const judgmentId = str(d.judgmentId) ?? (typeof d.id === "string" && d.id.startsWith("jdg_") ? d.id : null);
  const rest = Object.fromEntries(Object.entries(d).filter(([k]) => !["note", "decisionNote", "recipients", "emailedTo", "to", "threadId"].includes(k)));
  return (
    <div className="mt-1 space-y-1">
      {recipients && <div className="text-xs text-muted">Recipients: <span className="font-mono text-fg">{recipients}</span></div>}
      {note && <div className="text-xs italic text-fg">“{note}”</div>}
      <div className="flex flex-wrap gap-3 text-xs">
        {thread && <Link href={`/chat?thread=${encodeURIComponent(thread)}${actionId ? `&actionId=${encodeURIComponent(actionId)}` : ""}`} className="inline-flex items-center gap-1 text-blue-400 hover:underline"><MessageSquare className="size-3" /> View conversation</Link>}
        {judgmentId && <Link href={`/judgments/${encodeURIComponent(judgmentId)}`} className="text-blue-400 hover:underline">Open judgment</Link>}
        {reportId && <Link href={`/reports/${reportId}`} className="text-blue-400 hover:underline">Open report</Link>}
        {actionId && !thread && <Link href="/approvals" className="text-blue-400 hover:underline">View approvals</Link>}
      </div>
      {Object.keys(rest).length > 0 && (
        <details>
          <summary className="cursor-pointer text-[11px] text-dim">Raw data</summary>
          <pre className="mt-1 overflow-x-auto font-mono text-[11px] text-muted">{JSON.stringify(rest, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

export default function EventsPage() {
  const now = useNow();
  const [host, setHost] = useState("");
  const [kind, setKind] = useState("");
  const qs = new URLSearchParams({ limit: "300" });
  if (host) qs.set("hostId", host);
  if (kind && !kind.startsWith("group:")) qs.set("kind", kind);
  const { data, error, updatedAt } = usePoll<AuditEvent[]>(`/audit?${qs}`, 3000);
  const hosts = usePoll<HostSummary[]>("/hosts", 15000);
  const hostName = (id: string) => hosts.data?.find((h) => h.id === id)?.name ?? id;
  const group = kind.startsWith("group:") ? KIND_GROUPS.find((g) => g.label === kind.slice(6)) : null;
  // Filter client-side too, in case the brain ignores the query params.
  const rows = (data ?? []).filter((e) => (!host || e.hostId === host) && (group ? group.kinds.includes(e.kind) : !kind || e.kind === kind));

  return (
    <>
      <PageHeader title="Audit Log" icon={<ScrollText className="size-6 text-blue-400" />} sub="Chronological record of Sentinel activity, daemon telemetry and administrator decisions" right={<LiveTag updatedAt={updatedAt} error={error} now={now} />} />
      <ErrorBanner error={error} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select value={host} onChange={(e) => setHost(e.target.value)} className="h-8 rounded-lg border border-line bg-panel px-2 text-xs text-fg">
          <option value="">All Assets</option>
          {hosts.data?.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
        </select>
        <select value={kind} onChange={(e) => setKind(e.target.value)} className="h-8 rounded-lg border border-line bg-panel px-2 text-xs text-fg">
          <option value="">All Events</option>
          {KIND_GROUPS.map((g) => (
            <optgroup key={g.label} label={g.label}>
              <option value={`group:${g.label}`}>All {g.label.toLowerCase()}</option>
              {g.kinds.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}
            </optgroup>
          ))}
        </select>
        <span className="text-xs text-dim">{rows.length} events</span>
      </div>
      {!data ? (
        <Skeleton className="h-96" />
      ) : rows.length === 0 ? (
        <Empty>No events{host || kind ? " match the selected filters" : " recorded"}.</Empty>
      ) : (
        <Card className="overflow-hidden">
          <ol className="divide-y divide-line/60">
            {rows.map((e) => {
              const Icon = EVENT_ICON[e.kind] ?? Bug;
              return (
                <li key={e.id} className="grid grid-cols-[8.5rem_2rem_1fr] gap-3 px-4 py-3 hover:bg-panel-2/40">
                  <div className="text-xs text-muted" title={e.at}>
                    {fmtDate(e.at)}
                    <div className="text-dim">{relTime(e.at, now)}</div>
                  </div>
                  <div className={cn("flex size-8 items-center justify-center rounded-full bg-panel-2 ring-1 ring-line", EVENT_TONE[e.kind] ?? "text-muted")}>
                    <Icon className="size-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <ActorChip actor={e.actor} />
                      <span className={cn("font-mono text-[11px]", EVENT_TONE[e.kind] ?? "text-muted")}>{e.kind.replace(/_/g, " ")}</span>
                      {e.hostId && <Link href={`/hosts/${e.hostId}`} className="text-xs text-muted hover:text-fg hover:underline">{hostName(e.hostId)}</Link>}
                      {e.cveId && <span className="font-mono text-xs text-muted">{e.cveId}</span>}
                    </div>
                    <div className="mt-1 text-sm text-fg">{e.message}</div>
                    <Details e={e} />
                  </div>
                </li>
              );
            })}
          </ol>
        </Card>
      )}
    </>
  );
}
