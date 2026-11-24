"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import type { AdvisoryJudgment } from "@prohori/shared";
import { ArrowRight, CheckCircle2, Loader2, Scale, Search } from "lucide-react";
import { JudgmentStateBadge, VerdictCounts } from "@/components/judgment-card";
import { Badge, Button, Card, CardHeader, Empty, ErrorBanner, Input, LiveTag, PageHeader, Skeleton } from "@/components/ui";
import { api, useNow, usePoll } from "@/lib/api";
import { isJudgmentRunning, judgmentTitle, verdictCounts } from "@/lib/judgments";
import { actorLabel } from "@/lib/format";
import { cn, relTime } from "@/lib/utils";

function JudgeForm() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [cveId, setCveId] = useState("");
  const [focus, setFocus] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const urlOk = /^https:\/\/\S+$/i.test(url.trim());
  const cveOk = !cveId.trim() || /^CVE-\d{4}-\d{4,}$/i.test(cveId.trim());

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!urlOk || !cveOk || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const body: { url: string; cveId?: string; focus?: string } = { url: url.trim() };
      if (cveId.trim()) body.cveId = cveId.trim().toUpperCase();
      if (focus.trim()) body.focus = focus.trim();
      const j = await api<AdvisoryJudgment>("/judgments", { method: "POST", json: body });
      router.push(`/judgments/${encodeURIComponent(j.id)}`);
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
      setBusy(false);
    }
  }

  return (
    <Card className="mb-5">
      <CardHeader
        title="Judge an Advisory"
        icon={<Search className="size-4 text-blue-400" />}
        sub="Sentinel reads the advisory, matches it to installed packages on every asset, investigates each one with read-only tools and plans remediation. Nothing is changed on the assets."
      />
      <form onSubmit={submit} className="space-y-3 p-4">
        <div>
          <label className="mb-1 block text-xs font-medium text-muted">Advisory URL</label>
          <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://vendor.example/security/advisory-2026-01" className="font-mono" />
          {url.trim() && !urlOk && <p className="mt-1 text-[11px] text-amber-300">Enter a full https:// URL.</p>}
        </div>
        <div className="grid gap-3 md:grid-cols-[14rem_minmax(0,1fr)]">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">CVE ID <span className="text-dim">(optional)</span></label>
            <Input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2026-12345" className="font-mono" />
            {!cveOk && <p className="mt-1 text-[11px] text-amber-300">Use the form CVE-YYYY-NNNN.</p>}
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-muted">Focus <span className="text-dim">(optional: which bug, if the page lists several)</span></label>
            <Input value={focus} onChange={(e) => setFocus(e.target.value)} placeholder="e.g. the SRP authentication bypass" />
          </div>
        </div>
        {err && <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-sm text-red-200">{err}</div>}
        <div className="flex items-center justify-end gap-3">
          <span className="text-xs text-dim">Results arrive in a minute or two; you can leave the page.</span>
          <Button type="submit" variant="primary" loading={busy} disabled={!urlOk || !cveOk}>
            <Scale className="size-4" /> Judge Advisory
          </Button>
        </div>
      </form>
    </Card>
  );
}

export default function JudgmentsPage() {
  const now = useNow();
  const [fast, setFast] = useState(true);
  const list = usePoll<AdvisoryJudgment[]>("/judgments", fast ? 3000 : 15000);
  const rows = [...(list.data ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const anyRunning = !list.data || rows.some((j) => isJudgmentRunning(j));
  if (anyRunning !== fast) setFast(anyRunning);

  return (
    <>
      <PageHeader
        title="Advisory Judgments"
        icon={<Scale className="size-6 text-blue-400" />}
        sub="Judge a new advisory against your assets: what a version-only check would flag versus what is actually exposed"
        right={<LiveTag updatedAt={list.updatedAt} error={list.error} now={now} />}
      />
      <ErrorBanner error={list.error} />
      <JudgeForm />

      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-muted">Recent Judgments</h2>
      {!list.data ? (
        list.error ? <Empty>Judgments are unavailable right now.</Empty> : <Skeleton className="h-48" />
      ) : rows.length === 0 ? (
        <Empty>No advisories judged yet. Paste an advisory URL above, or ask Sentinel in chat.</Empty>
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-panel-2/60 text-left text-[11px] uppercase tracking-wider text-dim">
              <tr>
                <th className="px-4 py-2.5 font-semibold">State</th>
                <th className="px-4 py-2.5 font-semibold">Advisory</th>
                <th className="px-4 py-2.5 font-semibold">Version-Only vs Sentinel</th>
                <th className="px-4 py-2.5 font-semibold">Requested</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((j) => {
                const href = `/judgments/${encodeURIComponent(j.id)}`;
                const c = verdictCounts(j.hosts);
                const running = isJudgmentRunning(j);
                return (
                  <tr key={j.id} className={cn("group border-t border-line/70 align-top hover:bg-panel-2/60", c.exposed > 0 && "bg-red-500/[0.05]")}>
                    <td className="px-4 py-2.5">
                      <JudgmentStateBadge j={j} />
                      {running && j.progress && <div className="mt-1 max-w-[14rem] text-[11px] text-blue-200">{j.progress}</div>}
                      {j.state === "failed" && j.error && <div className="mt-1 max-w-[14rem] truncate text-[11px] text-red-300" title={j.error}>{j.error}</div>}
                    </td>
                    <td className="px-4 py-2.5">
                      <Link href={href} className="font-semibold text-white hover:underline">{judgmentTitle(j)}</Link>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-muted">{j.advisory?.cveId ?? (j.advisory ? "no CVE id" : "—")}</span>
                        {j.tracked && <Badge tone="green"><CheckCircle2 className="size-3" /> Tracked</Badge>}
                      </div>
                      <div className="max-w-[18rem] truncate font-mono text-[11px] text-dim" title={j.url}>{j.url}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      {j.hosts.length > 0 ? (
                        <>
                          <div className="mb-1 text-xs text-muted">
                            Version-only: <b className={c.naiveVulnerable ? "text-red-300" : "text-emerald-300"}>{c.naiveVulnerable} vulnerable</b>
                          </div>
                          <VerdictCounts j={j} />
                        </>
                      ) : running ? (
                        <span className="inline-flex items-center gap-1 text-xs text-dim"><Loader2 className="size-3 animate-spin" /> Pending</span>
                      ) : j.state === "done" ? (
                        <span className="text-xs text-muted">Not installed on any asset</span>
                      ) : (
                        <span className="text-xs text-dim">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted">
                      {actorLabel(j.requestedBy)}
                      <div className="text-dim" title={j.createdAt}>{relTime(j.createdAt, now)}</div>
                    </td>
                    <td className="px-2 py-2.5"><Link href={href}><ArrowRight className="size-4 text-dim group-hover:text-fg" /></Link></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          </div>
        </Card>
      )}
    </>
  );
}
