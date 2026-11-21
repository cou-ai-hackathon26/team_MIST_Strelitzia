"use client";

import { useEffect, useState } from "react";
import type { ActionType, Finding, Investigation, ThreatProfile } from "@prohori/shared";
import {
  Bot, CheckCircle2, CircleDashed, ExternalLink, Gavel, HelpCircle, Lock, ScrollText, ShieldAlert, Wrench, XCircle,
} from "lucide-react";
import { Badge, Card, CardHeader, KV, Skeleton } from "@/components/ui";
import { ApiError, api } from "@/lib/api";
import { actionTitle } from "@/lib/actions";
import { cn } from "@/lib/utils";

type Precondition = Investigation["preconditions"][number];
type PlanItem = Investigation["remediationPlan"][number];

const VECTOR_LABEL: Record<ThreatProfile["attackVector"], string> = {
  network: "Network (remote)",
  adjacent: "Adjacent network",
  local: "Local",
  physical: "Physical",
  unknown: "Unknown",
};

const normRef = (r: string) => r.trim().toUpperCase();

/** GET /api/profiles/:cveId once per CVE; 404 means Sentinel has not analysed the advisory (yet). */
function useThreatProfile(cveId: string) {
  const [state, setState] = useState<{ cveId: string; profile: ThreatProfile | null; missing: boolean; error: string | null } | null>(null);
  useEffect(() => {
    let live = true;
    api<ThreatProfile>(`/profiles/${encodeURIComponent(cveId)}`)
      .then((p) => live && setState({ cveId, profile: p, missing: false, error: null }))
      .catch((e: unknown) => {
        if (!live) return;
        if (e instanceof ApiError && e.status === 404) setState({ cveId, profile: null, missing: true, error: null });
        else setState({ cveId, profile: null, missing: false, error: e instanceof Error ? e.message : String(e) });
      });
    return () => { live = false; };
  }, [cveId]);
  return state?.cveId === cveId ? state : null;
}

function SectionTitle({ children, right }: { children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between gap-2">
      <h3 className="font-display text-[11px] uppercase tracking-wider text-dim">{children}</h3>
      {right}
    </div>
  );
}

function compactInput(input: Record<string, unknown>): string {
  const parts = Object.entries(input ?? {}).map(([k, v]) => {
    const s = typeof v === "string" ? v : JSON.stringify(v);
    return `${k}=${s && s.length > 60 ? `${s.slice(0, 57)}…` : s}`;
  });
  return parts.join(" · ");
}

function isUrl(s: string) {
  return /^https?:\/\//i.test(s);
}

export function PlanKindBadge({ kind }: { kind: PlanItem["kind"] }) {
  if (kind === "containment") return <Badge tone="blue"><Lock className="size-3" /> Containment</Badge>;
  if (kind === "fix") return <Badge tone="green">Full Remediation</Badge>;
  return <Badge tone="amber">Partial</Badge>;
}

const RESULT_META: Record<Precondition["result"], { label: string; icon: React.ReactNode; tone: "red" | "green" | "amber"; row: string }> = {
  met: { label: "Met", icon: <CheckCircle2 className="size-4 text-red-400" />, tone: "red", row: "border-red-500/30" },
  not_met: { label: "Not Met", icon: <XCircle className="size-4 text-emerald-400" />, tone: "green", row: "border-emerald-500/25" },
  unknown: { label: "Unknown", icon: <HelpCircle className="size-4 text-amber-400" />, tone: "amber", row: "border-amber-500/30" },
};

function ThreatProfileSection({ cveId, fallback }: { cveId: string; fallback: Investigation["profile"] | undefined }) {
  const st = useThreatProfile(cveId);
  if (!st) return <Skeleton className="h-28" />;
  const p = st.profile;
  if (!p) {
    if (fallback) {
      return (
        <div className="space-y-2">
          <p className="text-sm leading-relaxed text-fg">{fallback.summary}</p>
          <div className="rounded-lg border border-line bg-bg px-3 py-1">
            <KV k="Affected component" v={fallback.component} mono={false} />
            <KV k="Attack vector" v={VECTOR_LABEL[fallback.attackVector] ?? fallback.attackVector} mono={false} />
            <KV k="Complete fix" v={fallback.completeFix} mono={false} />
          </div>
          <p className="text-xs text-dim">{st.error ? `Full threat profile unavailable: ${st.error}` : "Full threat profile not available; showing the summary recorded with this investigation."}</p>
        </div>
      );
    }
    return <p className="text-sm text-muted">{st.error ? `Threat profile unavailable: ${st.error}` : "No threat profile recorded for this CVE yet."}</p>;
  }
  return (
    <div className="space-y-3">
      <p className="text-sm leading-relaxed text-fg">{p.summary}</p>
      <div className="rounded-lg border border-line bg-bg px-3 py-1">
        <KV k="Affected component" v={p.component} mono={false} />
        <KV k="Attack vector" v={VECTOR_LABEL[p.attackVector] ?? p.attackVector} mono={false} />
        <KV k="Exploited in the wild" v={p.exploitedInWild ? <Badge tone="red">Yes · Exploitation Reported</Badge> : <Badge tone="gray">No Reports</Badge>} mono={false} />
        <KV k="Complete fix" v={<span className="text-emerald-200">{p.completeFix}</span>} mono={false} />
      </div>
      {p.partialMitigations.length > 0 && (
        <div>
          <div className="mb-1.5 text-xs font-medium text-muted">Partial Mitigations</div>
          <ul className="space-y-1.5">
            {p.partialMitigations.map((m, i) => (
              <li key={i} className="rounded-lg border border-line px-3 py-2 text-sm">
                <div className="flex items-start gap-2">
                  <Badge tone="amber" className="mt-0.5 shrink-0">Partial</Badge>
                  <span className="text-fg">{m.text}</span>
                </div>
                {m.tradeoff && <div className="mt-1 text-xs text-amber-200/80">Trade-off: {m.tradeoff}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {p.sources.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-dim">Sources:</span>
          {p.sources.map((s, i) =>
            isUrl(s) ? (
              <a key={i} href={s} target="_blank" rel="noreferrer" className="inline-flex max-w-[22rem] items-center gap-1 truncate rounded border border-line bg-bg px-1.5 py-0.5 font-mono text-[11px] text-blue-300 hover:underline">
                <span className="truncate">{s.replace(/^https?:\/\//, "")}</span>
                <ExternalLink className="size-3 shrink-0" />
              </a>
            ) : (
              <span key={i} className="rounded border border-line bg-bg px-1.5 py-0.5 font-mono text-[11px] text-muted">{s}</span>
            ),
          )}
        </div>
      )}
    </div>
  );
}

/** "Sentinel's Investigation": triage → threat profile → precondition checks → tool steps → conclusion → plan. */
export function InvestigationPanel({ finding, hostName }: { finding: Finding; hostName: string }) {
  const inv = finding.investigation;
  const [hovered, setHovered] = useState<string | null>(null);
  const [pinned, setPinned] = useState<string | null>(null);
  const active = hovered ?? pinned;

  const header = (
    <CardHeader
      title="Sentinel's Investigation"
      icon={<Bot className="size-4 text-violet-400" />}
      sub="How Sentinel reached this verdict: advisory analysis, checks run on the asset and code guardrails"
    />
  );

  if (!inv) {
    return (
      <Card>
        {header}
        <div className="flex items-center gap-2 px-4 py-6 text-sm text-muted">
          <CircleDashed className="size-4 text-dim" /> No investigation recorded for this finding.
        </div>
      </Card>
    );
  }

  const knownRefs = new Set(inv.steps.map((s) => normRef(s.ref)));
  function chip(ref: string, key: string | number) {
    const r = normRef(ref);
    const known = knownRefs.has(r);
    return (
      <button
        key={key}
        type="button"
        disabled={!known}
        title={known ? `Show step ${r}` : `Step ${r} not recorded`}
        onMouseEnter={() => setHovered(r)}
        onMouseLeave={() => setHovered(null)}
        onFocus={() => setHovered(r)}
        onBlur={() => setHovered(null)}
        onClick={() => {
          setPinned((p) => (p === r ? null : r));
          document.getElementById(`inv-step-${r}`)?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        }}
        className={cn(
          "rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none transition-colors",
          known ? "cursor-pointer border-violet-500/40 bg-violet-500/10 text-violet-200 hover:bg-violet-500/25" : "cursor-not-allowed border-line text-dim line-through",
          active === r && "border-violet-400 bg-violet-500/30 text-white",
        )}
      >
        {r}
      </button>
    );
  }

  const triageBySentinel = inv.triage.decidedBy === "sentinel";

  return (
    <Card>
      {header}
      <div className="divide-y divide-line">
        {/* Triage */}
        <section className="p-4">
          <SectionTitle>Triage</SectionTitle>
          <div className="flex flex-wrap items-start gap-2 text-sm">
            {triageBySentinel ? (
              <Badge tone="violet"><Bot className="size-3" /> Decided by Sentinel</Badge>
            ) : (
              <Badge tone="gray"><Gavel className="size-3" /> Decided by Floor Rule</Badge>
            )}
            <span className="min-w-0 flex-1 text-fg">{inv.triage.reason}</span>
          </div>
        </section>

        {/* Threat profile */}
        <section className="p-4">
          <SectionTitle right={<span className="inline-flex items-center gap-1 text-[11px] text-dim"><ScrollText className="size-3" /> Derived from the advisory</span>}>
            Threat Profile
          </SectionTitle>
          <ThreatProfileSection cveId={finding.cveId} fallback={inv.profile} />
        </section>

        {/* Preconditions */}
        <section className="p-4">
          <SectionTitle right={<span className="text-[11px] text-dim">Chips cite the steps below</span>}>Preconditions Checked on {hostName}</SectionTitle>
          {inv.preconditions.length === 0 ? (
            <p className="text-sm text-muted">No preconditions were evaluated.</p>
          ) : (
            <ul className="space-y-2">
              {inv.preconditions.map((pc) => {
                const meta = RESULT_META[pc.result] ?? RESULT_META.unknown;
                return (
                  <li key={pc.id} className={cn("rounded-lg border bg-bg/40 px-3 py-2", meta.row)}>
                    <div className="flex items-start gap-2">
                      <span className="mt-0.5 shrink-0">{meta.icon}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm font-medium text-fg">{pc.text}</span>
                          <Badge tone={meta.tone} className="uppercase">{meta.label}</Badge>
                        </div>
                        {pc.note && <p className="mt-1 text-xs leading-relaxed text-muted">{pc.note}</p>}
                        {pc.evidence.length > 0 ? (
                          <div className="mt-1.5 flex flex-wrap items-center gap-1">
                            <span className="text-[11px] text-dim">Evidence</span>
                            {pc.evidence.map((r, i) => chip(r, i))}
                          </div>
                        ) : (
                          <div className="mt-1.5 text-[11px] text-amber-300/80">No cited evidence</div>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* Steps */}
        <section className="p-4">
          <SectionTitle right={<span className="text-[11px] text-dim">Read-only tools</span>}>Investigation Steps</SectionTitle>
          {inv.steps.length === 0 ? (
            <p className="text-sm text-muted">No tool steps recorded.</p>
          ) : (
            <ol className="relative space-y-2 border-l border-line pl-4">
              {inv.steps.map((s, i) => {
                const r = normRef(s.ref);
                const on = active === r;
                return (
                  <li
                    key={`${r}-${i}`}
                    id={`inv-step-${r}`}
                    onMouseEnter={() => setHovered(r)}
                    onMouseLeave={() => setHovered(null)}
                    className={cn(
                      "relative scroll-mt-24 rounded-lg border px-3 py-2 transition-colors",
                      on ? "border-violet-400/70 bg-violet-500/10 ring-1 ring-violet-400/40" : "border-line bg-bg/40",
                    )}
                  >
                    <span className={cn("absolute -left-[21px] top-3 size-2.5 rounded-full border", on ? "border-violet-300 bg-violet-400" : "border-line-2 bg-panel")} />
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded border border-violet-500/40 bg-violet-500/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold leading-none text-violet-200">{r}</span>
                      <span className="font-mono text-xs text-fg">{s.tool}</span>
                      {Object.keys(s.input ?? {}).length > 0 && (
                        <span className="min-w-0 truncate font-mono text-[11px] text-dim" title={JSON.stringify(s.input)}>{compactInput(s.input)}</span>
                      )}
                    </div>
                    <p className="mt-1 text-sm text-muted">{s.summary}</p>
                  </li>
                );
              })}
            </ol>
          )}
        </section>

        {/* Conclusion + guardrail */}
        <section className="space-y-3 p-4">
          <SectionTitle>Conclusion</SectionTitle>
          <p className="text-sm leading-relaxed text-fg">{inv.conclusion || "No conclusion recorded."}</p>
          {inv.guardrail && (
            <div className="flex items-start gap-2 rounded-lg border border-amber-500/50 bg-amber-950/30 px-3 py-2 text-sm text-amber-100">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-400" />
              <span><b className="font-semibold text-amber-200">Code guardrail:</b> {inv.guardrail}</span>
            </div>
          )}
        </section>

        {/* Remediation plan */}
        <section className="p-4">
          <SectionTitle right={<span className="inline-flex items-center gap-1 text-[11px] text-dim"><Wrench className="size-3" /> Ranked by Sentinel</span>}>Remediation Plan</SectionTitle>
          {inv.remediationPlan.length === 0 ? (
            <p className="text-sm text-muted">No remediation required.</p>
          ) : (
            <ol className="space-y-2">
              {inv.remediationPlan.map((item, i) => (
                <li key={i} className={cn("flex gap-3 rounded-lg border p-3", item.kind === "fix" ? "border-emerald-500/40 bg-emerald-950/20" : "border-line")}>
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-full border border-line-2 bg-panel-2 text-xs font-bold tabular-nums text-fg">{i + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <PlanKindBadge kind={item.kind} />
                      <span className="text-sm font-medium text-fg">{item.summary}</span>
                    </div>
                    {item.tradeoff && <p className="mt-1 text-xs text-muted"><span className="text-dim">Trade-off:</span> {item.tradeoff}</p>}
                    {item.actionType ? (
                      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                        <span className="rounded border border-line bg-bg px-1.5 py-0.5 font-mono text-[11px] text-fg">{item.actionType}</span>
                        {item.params && <span className="text-muted">{actionTitle({ type: item.actionType as ActionType, params: item.params }, hostName)}</span>}
                      </div>
                    ) : (
                      <div className="mt-1.5 text-[11px] text-dim">Manual step · no automated action</div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </Card>
  );
}
