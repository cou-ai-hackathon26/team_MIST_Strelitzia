"use client";

import type { ActionRecord, Finding, HostSummary } from "@prohori/shared";
import { CheckSquare, ShieldAlert } from "lucide-react";
import { ActionCard } from "@/components/action-card";
import { Empty, ErrorBanner, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { useNow, usePoll } from "@/lib/api";
import { actionKind } from "@/lib/actions";

const KIND_ORDER = { containment: 0, fix: 1, partial: 2, other: 3 } as const;

export default function ApprovalsPage() {
  const now = useNow();
  const actions = usePoll<ActionRecord[]>("/actions");
  const hosts = usePoll<HostSummary[]>("/hosts", 15000);
  const findings = usePoll<Finding[]>("/findings", 5000);
  const hostName = (id: string) => hosts.data?.find((h) => h.id === id)?.name ?? id;
  const findingOf = (a: ActionRecord) => findings.data?.find((f) => f.id === a.findingId) ?? null;
  const all = actions.data ?? [];
  const inFlight = all.filter((a) => a.state === "pending" || a.state === "approved" || a.state === "running");
  inFlight.sort((a, b) => KIND_ORDER[actionKind(a)] - KIND_ORDER[actionKind(b)] || b.createdAt.localeCompare(a.createdAt));
  const decided = all
    .filter((a) => !inFlight.includes(a))
    .sort((a, b) => (b.decidedAt ?? b.createdAt).localeCompare(a.decidedAt ?? a.createdAt));

  return (
    <>
      <PageHeader title="Approvals" icon={<CheckSquare className="size-6 text-blue-400" />} sub="Remediation proposed by Sentinel. Review each change in conversation; every approval is attributed and logged." right={<LiveTag updatedAt={actions.updatedAt} error={actions.error} now={now} />} />
      <div className="mb-5 flex items-start gap-2 rounded-lg border border-line bg-panel px-3 py-2.5 text-xs text-muted">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-blue-400" />
        <span>
          <b className="text-fg">Human-in-the-loop control.</b> Sentinel can only <i>propose</i> actions from a fixed allowlist (close a firewall port, upgrade packages, block multipart uploads, set an allow-listed configuration directive such as a php.ini or sshd_config option, restart a service) and can revise a proposal on request. It cannot approve or execute changes. A named administrator approves after review; the daemon on each asset re-validates every parameter locally and records a rollback point. Every decision is recorded in the Audit Log.
        </span>
      </div>
      <ErrorBanner error={actions.error} />
      {!actions.data ? (
        <Skeleton className="h-48" />
      ) : (
        <>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted">Awaiting Decision ({inFlight.filter((a) => a.state === "pending").length})</h2>
          <div className="mb-8 space-y-4">
            {inFlight.length === 0 ? (
              <Empty>No actions awaiting approval. Ask Sentinel to recommend remediation.</Empty>
            ) : (
              inFlight.map((a) => <ActionCard key={a.id} a={a} hostName={hostName(a.hostId)} mode="list" finding={findingOf(a)} onChange={() => void actions.refresh()} />)
            )}
          </div>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted">Decision History ({decided.length})</h2>
          <div className="space-y-4">
            {decided.length === 0 ? <Empty>No decisions recorded.</Empty> : decided.map((a) => <ActionCard key={a.id} a={a} hostName={hostName(a.hostId)} mode="list" finding={findingOf(a)} onChange={() => void actions.refresh()} compact />)}
          </div>
        </>
      )}
    </>
  );
}
