"use client";

import { useEffect, useState } from "react";
import type { EnrollResponse, Settings, StatusResponse } from "@prohori/shared";
import { Copy, ExternalLink, FlaskConical, Mail, Plus, RotateCcw, Save, Server, Settings as SettingsIcon, Sparkles, Trash2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, ErrorBanner, Input, PageHeader, Skeleton } from "@/components/ui";
import { api, usePoll } from "@/lib/api";
import { cn } from "@/lib/utils";

function useFlash() {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => {
    if (!msg) return;
    const t = setTimeout(() => setMsg(null), 5000);
    return () => clearTimeout(t);
  }, [msg]);
  return [msg, setMsg] as const;
}

function Flash({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null;
  return <span className={cn("text-sm", msg.ok ? "text-emerald-300" : "text-red-300")}>{msg.text}</span>;
}

function CopyBtn({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button size="sm" variant="ghost" onClick={() => { void navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      <Copy className="size-3.5" /> {done ? "copied" : "copy"}
    </Button>
  );
}

function SettingsForm() {
  const { data, error, refresh } = usePoll<Settings>("/settings", 0);
  const [form, setForm] = useState<Settings | null>(null);
  const [newEmail, setNewEmail] = useState("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useFlash();

  useEffect(() => {
    if (data && !form) setForm(data);
  }, [data, form]);

  async function save(patch?: Partial<Settings>) {
    if (!form) return;
    const body = patch ?? { reportEmails: form.reportEmails, scanIntervalSec: form.scanIntervalSec, tier2Enabled: form.tier2Enabled };
    setSaving(true);
    try {
      const s = await api<Settings>("/settings", { method: "PUT", json: body });
      setForm(s);
      await refresh();
      setMsg({ ok: true, text: "Saved" });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  }

  function addEmail() {
    const e = newEmail.trim();
    if (!form || !e || !/^[^\s@]+@[^\s@]+$/.test(e) || form.reportEmails.includes(e)) return;
    setForm({ ...form, reportEmails: [...form.reportEmails, e] });
    setNewEmail("");
  }

  return (
    <Card>
      <CardHeader title="Scanning & reports" icon={<SettingsIcon className="size-4 text-blue-400" />} />
      <div className="space-y-5 p-4">
        <ErrorBanner error={error} />
        {!form ? (
          <Skeleton className="h-40" />
        ) : (
          <>
            <div>
              <label className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-dim"><Mail className="size-3.5" /> Report recipients</label>
              <div className="space-y-1.5">
                {form.reportEmails.map((e) => (
                  <div key={e} className="flex items-center gap-2 rounded-lg border border-line bg-bg px-3 py-1.5 text-sm">
                    <span className="flex-1 font-mono">{e}</span>
                    <button onClick={() => setForm({ ...form, reportEmails: form.reportEmails.filter((x) => x !== e) })} className="text-dim hover:text-red-300" title="remove"><Trash2 className="size-3.5" /></button>
                  </div>
                ))}
                {form.reportEmails.length === 0 && <div className="text-sm text-amber-300">No recipients — reports will not be emailed.</div>}
              </div>
              <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); addEmail(); }}>
                <Input type="email" placeholder="it-team@bank.example" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
                <Button type="submit"><Plus className="size-4" /> Add</Button>
              </form>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-dim">Scan interval (seconds)</label>
                <Input type="number" min={10} value={form.scanIntervalSec} onChange={(e) => setForm({ ...form, scanIntervalSec: Math.max(10, Number(e.target.value) || 0) })} />
                <div className="mt-1 text-xs text-muted">KEV feed refresh: every {form.wildRefreshSec}s</div>
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-dim">Tier-2: propose & apply fixes</label>
                <button
                  onClick={() => setForm({ ...form, tier2Enabled: !form.tier2Enabled })}
                  className={cn("flex h-9 w-full items-center gap-3 rounded-lg border px-3 text-sm", form.tier2Enabled ? "border-violet-500/50 bg-violet-500/10" : "border-line-2 bg-bg")}
                >
                  <span className={cn("relative h-5 w-9 rounded-full transition-colors", form.tier2Enabled ? "bg-violet-500" : "bg-slate-600")}>
                    <span className={cn("absolute top-0.5 size-4 rounded-full bg-white transition-all", form.tier2Enabled ? "left-4.5" : "left-0.5")} />
                  </span>
                  {form.tier2Enabled ? "Enabled (human approval required)" : "Disabled (read-only)"}
                </button>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={() => save()} loading={saving}><Save className="size-4" /> Save settings</Button>
              <Flash msg={msg} />
            </div>
          </>
        )}
      </div>
    </Card>
  );
}

function EnrollForm() {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<EnrollResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function enroll(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      setRes(await api<EnrollResponse>("/hosts/enroll", { method: "POST", json: { name: name.trim() } }));
      setName("");
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : String(e2));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader title="Add host" icon={<Server className="size-4 text-blue-400" />} sub="Creates a host id and a one-time enrollment token for the Prohori daemon" />
      <div className="space-y-3 p-4">
        <form onSubmit={enroll} className="flex gap-2">
          <Input placeholder="Display name, e.g. bank-web-03" value={name} onChange={(e) => setName(e.target.value)} />
          <Button type="submit" variant="primary" loading={busy} disabled={!name.trim()}><Plus className="size-4" /> Enroll</Button>
        </form>
        {err && <p className="text-sm text-red-300">{err}</p>}
        {res && (
          <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-950/20 p-3">
            <div className="text-xs font-semibold text-amber-300">Shown once — copy it now.</div>
            <div className="text-sm">Host id: <span className="font-mono text-white">{res.hostId}</span></div>
            <div className="flex items-center gap-2 text-sm">Token: <code className="flex-1 truncate rounded bg-bg px-2 py-1 font-mono text-xs">{res.token}</code><CopyBtn text={res.token} /></div>
            <div>
              <div className="mb-1 flex items-center justify-between text-xs text-muted">Install command <CopyBtn text={res.installCommand} /></div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded bg-bg p-2 font-mono text-xs">{res.installCommand}</pre>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

function DemoPanel() {
  const status = usePoll<StatusResponse>("/status", 3000);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useFlash();
  const demo = status.data?.demo;

  async function run(kind: "inject" | "reset") {
    if (kind === "reset" && !confirm("Reset the demo? This re-holds PHP2Shell and deletes its findings, reports and actions.")) return;
    setBusy(kind);
    try {
      if (kind === "inject") {
        const r = await api<{ injected: string[] }>("/demo/inject", { method: "POST", json: {} });
        setMsg({ ok: true, text: `Released ${r.injected.join(", ") || "nothing"} — the next scan will discover it` });
      } else {
        await api("/demo/reset", { method: "POST" });
        setMsg({ ok: true, text: "Demo reset" });
      }
      await status.refresh();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card className="border-violet-500/40">
      <CardHeader title="Demo panel" icon={<FlaskConical className="size-4 text-violet-400" />} sub="Replay the real PHP2Shell disclosure (Oct 21 2026) against the lab servers" />
      <div className="space-y-4 p-4">
        <div className="flex flex-wrap gap-2">
          <Button variant="danger" size="lg" onClick={() => run("inject")} loading={busy === "inject"} disabled={!!busy || (demo ? demo.replayHeld.length === 0 : false)}>
            <Sparkles className="size-4" /> Inject PHP2Shell (replay Oct 21 disclosure)
          </Button>
          <Button variant="secondary" size="lg" onClick={() => run("reset")} loading={busy === "reset"} disabled={!!busy}>
            <RotateCcw className="size-4" /> Reset demo
          </Button>
        </div>
        <Flash msg={msg} />
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-line bg-bg p-3">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Held back (not yet "published")</div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {demo?.replayHeld.length ? demo.replayHeld.map((c) => <Badge key={c} tone="gray" className="font-mono">{c}</Badge>) : <span className="text-sm text-muted">none</span>}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-bg p-3">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-dim">Injected (visible to scans)</div>
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {demo?.injected.length ? demo.injected.map((c) => <Badge key={c} tone="violet" className="font-mono">{c}</Badge>) : <span className="text-sm text-muted">none</span>}
            </div>
          </div>
        </div>
        <a href="http://127.0.0.1:8025" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:underline">
          <Mail className="size-4" /> Open the mailbox (Mailpit) — http://127.0.0.1:8025 <ExternalLink className="size-3.5" />
        </a>
      </div>
    </Card>
  );
}

export default function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" icon={<SettingsIcon className="size-6 text-blue-400" />} sub="Recipients, scan schedule, Tier-2 fixes, host enrollment and the demo controls" />
      <div className="grid gap-5 xl:grid-cols-2">
        <div className="space-y-5">
          <SettingsForm />
          <EnrollForm />
        </div>
        <DemoPanel />
      </div>
    </>
  );
}
