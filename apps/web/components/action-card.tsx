"use client";

import Link from "next/link";
import { useState } from "react";
import type { ActionRecord, Finding } from "@prohori/shared";
import { Bot, Check, Loader2, Lock, MessageSquare, Undo2, User, X } from "lucide-react";
import { FlashOnChange } from "@/components/flash";
import { Badge, Button, Card, StatusPill } from "@/components/ui";
import { api, refreshAllPolls, usePoll } from "@/lib/api";
import { STATE_TONE, actionConsequence, actionKind, actionTitle } from "@/lib/actions";
import { cn, fmtDate, relTime } from "@/lib/utils";
import { ActionFixProgress } from "@/components/fix-progress";

function DiffBlock({ diff }: { diff: string }) {
  return (
    <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[11px] leading-relaxed">
      {diff.split("\n").map((l, i) => (
        <div key={i} className={cn(l.startsWith("+") && !l.startsWith("+++") ? "text-emerald-300" : l.startsWith("-") && !l.startsWith("---") ? "text-red-300" : "text-muted")}>{l || " "}</div>
      ))}
    </pre>
  );
}

export function KindBadge({ a }: { a: Pick<ActionRecord, "type"> }) {
  const k = actionKind(a);
  if (k === "containment") return <Badge tone="blue"><Lock className="size-3" /> containment</Badge>;
  if (k === "fix") return <Badge tone="green">complete fix</Badge>;
  if (k === "partial") return <Badge tone="amber">partial mitigation</Badge>;
  return null;
}

export function StateBadge({ state }: { state: ActionRecord["state"] }) {
  return (
    <FlashOnChange value={state}>
      <Badge tone={STATE_TONE[state]} className="uppercase">
        {(state === "running" || state === "approved") && <Loader2 className="size-3 animate-spin" />}
        {state.replace("_", " ")}
      </Badge>
    </FlashOnChange>
  );
}

function ParamList({ params }: { params: Record<string, unknown> }) {
  const entries = Object.entries(params);
  if (entries.length === 0) return <span className="text-xs text-dim">no parameters</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([k, v]) => (
        <span key={k} className="rounded-md border border-line bg-bg px-2 py-0.5 font-mono text-[11px]">
          <span className="text-dim">{k}=</span>
          <span className="text-fg">{Array.isArray(v) ? v.join(", ") : String(v)}</span>
        </span>
      ))}
    </div>
  );
}

/** Confirm dialog: shows the exact change, an optional note, then POSTs approve/reject with { note, threadId }. */
function DecideDialog({
  a, hostName, verb, threadId, onClose, onDone,
}: { a: ActionRecord; hostName: string; verb: "approve" | "reject"; threadId: string | null; onClose: () => void; onDone: (a: ActionRecord) => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function confirm() {
    setBusy(true);
    setErr(null);
    try {
      const res = await api<ActionRecord>(`/actions/${encodeURIComponent(a.id)}/${verb}`, {
        method: "POST",
        json: { note: note.trim() || undefined, threadId: threadId ?? a.threadId ?? undefined },
      });
      onDone(res);
      onClose();
      refreshAllPolls();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-line-2 bg-panel shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="border-b border-line px-5 py-4">
          <div className="text-xs font-semibold uppercase tracking-wider text-dim">{verb === "approve" ? "Approve and apply this change" : "Reject this proposal"}</div>
          <div className="mt-1 text-lg font-semibold text-white">{actionTitle(a, hostName)}</div>
        </div>
        <div className="space-y-3 px-5 py-4 text-sm">
          <div className="rounded-lg border border-line bg-bg p-3">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-dim">Exact change · <span className="font-mono normal-case">{a.type}</span></div>
            <pre className="whitespace-pre-wrap font-mono text-xs text-fg">{JSON.stringify(a.params, null, 2)}</pre>
          </div>
          {verb === "approve" && <p className={cn("text-sm", actionKind(a) === "fix" ? "text-emerald-200" : "text-amber-200")}>{actionConsequence(a)}</p>}
          <div>
            <label className="mb-1 block text-xs text-muted" htmlFor="note">Note (optional, saved in the event log)</label>
            <textarea id="note" rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder={verb === "approve" ? "e.g. approved during incident call, upgrade tonight" : "e.g. revise to block only uploads"} className="w-full rounded-lg border border-line-2 bg-bg px-3 py-2 text-sm text-fg placeholder:text-dim focus:border-accent focus:outline-none" />
          </div>
          {err && <p className="text-sm text-red-300">{err}</p>}
        </div>
        <div className="flex justify-end gap-2 border-t border-line px-5 py-3">
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant={verb === "approve" ? "success" : "danger"} onClick={confirm} loading={busy}>
            {verb === "approve" ? <Check className="size-4" /> : <X className="size-4" />} Confirm {verb}
          </Button>
        </div>
      </div>
    </div>
  );
}

export type ActionCardMode =
  | "list"    // approvals list: pending → "Review with Sentinel"; applied → Rollback
  | "decide"; // chat: pending → Approve / Reject (with confirm dialog); applied → Rollback

export function ActionCard({
  a, hostName, mode, finding, threadId, onChange, className, compact,
}: {
  a: ActionRecord;
  hostName: string;
  mode: ActionCardMode;
  finding?: Finding | null;
  threadId?: string | null;
  onChange?: (a: ActionRecord) => void;
  className?: string;
  compact?: boolean;
}) {
  const [dialog, setDialog] = useState<"approve" | "reject" | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showOut, setShowOut] = useState(false);
  const pending = a.state === "pending";
  const reviewHref = a.threadId ? `/chat?actionId=${encodeURIComponent(a.id)}&thread=${encodeURIComponent(a.threadId)}` : `/chat?actionId=${encodeURIComponent(a.id)}`;

  async function rollback() {
    if (!confirm(`Roll back "${actionTitle(a, hostName)}"?`)) return;
    setBusy(true);
    setErr(null);
    try {
      onChange?.(await api<ActionRecord>(`/actions/${encodeURIComponent(a.id)}/rollback`, { method: "POST", json: {} }));
      refreshAllPolls();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className={cn("overflow-hidden", pending && "border-amber-500/50", a.state === "superseded" && "opacity-70", className)}>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <StateBadge state={a.state} />
        <ActionFixProgress actionId={a.id} hostName={hostName} />
        <span className="font-semibold text-white">{actionTitle(a, hostName)}</span>
        <KindBadge a={a} />
        {a.supersedes && <Badge tone="violet">revision of {a.supersedes}</Badge>}
        <span className="ml-auto inline-flex items-center gap-1 text-xs text-dim">
          {a.proposedBy === "agent" ? <Bot className="size-3.5" /> : <User className="size-3.5" />} proposed by {a.proposedBy === "agent" ? "Sentinel" : "admin"} · {relTime(a.createdAt, Date.now())}
        </span>
      </div>
      <div className="grid gap-4 p-4 md:grid-cols-[1fr_auto]">
        <div className="min-w-0 space-y-3">
          {a.state === "superseded" && (
            <div className="rounded-lg border border-line bg-bg px-3 py-2 text-xs text-muted">
              {a.decisionNote
                ? <>Closed by Sentinel — {a.decisionNote}</>
                : <>Superseded by revision <span className="font-mono text-fg">{a.supersededBy ?? "…"}</span></>}
            </div>
          )}
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Why Sentinel proposed it</div>
            <p className="mt-0.5 text-sm text-fg">{a.reason}</p>
          </div>
          {actionKind(a) !== "fix" && actionConsequence(a) && (pending || !compact) && (
            <div className={cn("rounded-lg border px-3 py-2 text-xs", actionKind(a) === "containment" ? "border-blue-500/40 bg-blue-950/30 text-blue-100" : "border-amber-500/40 bg-amber-950/20 text-amber-100")}>
              {actionConsequence(a)}
            </div>
          )}
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-dim">Parameters · <span className="font-mono normal-case">{a.type}</span></div>
            <ParamList params={a.params} />
          </div>
          {(finding || a.findingId) && (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-dim">Finding:</span>
              <Link href={`/findings/${a.findingId}`} className="font-mono text-blue-400 hover:underline">{finding?.cveId ?? a.findingId}</Link>
              {finding && <FlashOnChange value={finding.status}><StatusPill status={finding.status} /></FlashOnChange>}
            </div>
          )}
          {a.decidedBy && a.state !== "superseded" && (
            <div className="rounded-lg border border-line bg-bg px-3 py-2 text-xs">
              <span className="text-muted">{a.state === "rejected" ? "Rejected" : "Approved"} by </span>
              <b className="text-fg">{a.decidedBy ?? "unknown"}</b>
              {a.decidedAt && <span className="text-muted"> · {fmtDate(a.decidedAt)}</span>}
              {a.decisionNote && <div className="mt-1 italic text-fg">“{a.decisionNote}”</div>}
            </div>
          )}
          {a.rolledBackBy && <div className="text-xs text-violet-300">Rolled back by <b>{a.rolledBackBy}</b></div>}
          {a.result && (
            <div>
              <div className="mb-1 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-dim">
                Result from daemon {a.result.ok ? <Badge tone="green">ok</Badge> : <Badge tone="red">failed</Badge>}
              </div>
              {a.result.diff && <DiffBlock diff={a.result.diff} />}
              {a.result.output && (
                <>
                  <button onClick={() => setShowOut((s) => !s)} className="mt-1 text-xs text-muted hover:text-fg">{showOut ? "hide" : "show"} command output</button>
                  {showOut && <pre className="mt-1 max-h-64 overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[11px] text-muted">{a.result.output}</pre>}
                </>
              )}
            </div>
          )}
          {a.threadId && mode === "list" && (
            <Link href={`/chat?thread=${encodeURIComponent(a.threadId)}&actionId=${encodeURIComponent(a.id)}`} className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline">
              <MessageSquare className="size-3.5" /> view discussion
            </Link>
          )}
          {err && <p className="text-sm text-red-300">{err}</p>}
        </div>
        <div className="flex flex-row gap-2 md:flex-col">
          {pending && mode === "list" && (
            <Link href={reviewHref}><Button variant="primary" size="lg"><MessageSquare className="size-4" /> Review with Sentinel</Button></Link>
          )}
          {pending && mode === "decide" && (
            <>
              <Button variant="success" onClick={() => setDialog("approve")}><Check className="size-4" /> Approve</Button>
              <Button variant="secondary" onClick={() => setDialog("reject")}><X className="size-4" /> Reject</Button>
            </>
          )}
          {!pending && mode === "decide" && (a.state === "approved" || a.state === "running" || a.state === "applied") && (
            <Button variant="success" disabled><Check className="size-4" /> {a.state === "applied" ? "Approved · applied" : "Approved · applying…"}</Button>
          )}
          {!pending && mode === "decide" && a.state === "rejected" && (
            <Button variant="secondary" disabled><X className="size-4" /> Rejected</Button>
          )}
          {!pending && mode === "decide" && a.state === "superseded" && (
            <Button variant="secondary" disabled>Closed</Button>
          )}
          {a.state === "applied" && (
            <Button variant="warning" onClick={rollback} loading={busy}><Undo2 className="size-4" /> Rollback</Button>
          )}
        </div>
      </div>
      {dialog && (
        <DecideDialog a={a} hostName={hostName} verb={dialog} threadId={threadId ?? null} onClose={() => setDialog(null)} onDone={(x) => onChange?.(x)} />
      )}
    </Card>
  );
}

/** ActionCard that keeps itself fresh by polling GET /api/actions/:id (used for tool outputs in chat). */
export function LiveActionCard({ initial, hostName, threadId, finding }: { initial: ActionRecord; hostName: string; threadId?: string | null; finding?: Finding | null }) {
  const live = usePoll<ActionRecord>(`/actions/${encodeURIComponent(initial.id)}`, 3000);
  const a = live.data ?? initial;
  return <ActionCard a={a} hostName={hostName} mode="decide" threadId={threadId} finding={finding} onChange={() => void live.refresh()} compact />;
}
