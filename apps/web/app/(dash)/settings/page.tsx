"use client";

import { useEffect, useState } from "react";
import type { EnrollResponse, Settings, StatusResponse } from "@prohori/shared";
import { Copy, ExternalLink, FlaskConical, Mail, Plus, Power, RotateCcw, Save, Server, Settings as SettingsIcon, Sparkles, Trash2 } from "lucide-react";
import { Badge, Button, Card, CardHeader, ErrorBanner, Input, PageHeader, Skeleton } from "@/components/ui";
import { api, refreshAllPolls, usePoll } from "@/lib/api";
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
      <Copy className="size-3.5" /> {done ? "Copied" : "Copy"}
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
    const body = patch ?? { reportEmails: form.reportEmails, scanIntervalSec: form.scanIntervalSec };
    setSaving(true);
    try {
      const s = await api<Settings>("/settings", { method: "PUT", json: body });
      setForm(s);
      await refresh();
      setMsg({ ok: true, text: "Settings saved" });
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
      <CardHeader title="Scanning & Reporting" icon={<SettingsIcon className="size-4 text-blue-400" />} />
      <div className="space-y-5 p-4">
        <ErrorBanner error={error} />
        {!form ? (
          <Skeleton className="h-40" />
        ) : (
          <>
            <div>
              <label className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-dim"><Mail className="size-3.5" /> Report Recipients</label>
              <div className="space-y-1.5">
                {form.reportEmails.map((e) => (
                  <div key={e} className="flex items-center gap-2 rounded-lg border border-line bg-bg px-3 py-1.5 text-sm">
                    <span className="flex-1 font-mono">{e}</span>
                    <button onClick={() => setForm({ ...form, reportEmails: form.reportEmails.filter((x) => x !== e) })} className="text-dim hover:text-red-300" title="Remove recipient"><Trash2 className="size-3.5" /></button>
                  </div>
                ))}
                {form.reportEmails.length === 0 && <div className="text-sm text-amber-300">No recipients configured. Reports will not be delivered.</div>}
              </div>
              <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); addEmail(); }}>
                <Input type="email" placeholder="security-team@bank.example" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
                <Button type="submit"><Plus className="size-4" /> Add</Button>
              </form>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wider text-dim">Scan Interval (Seconds)</label>
                <Input type="number" min={10} value={form.scanIntervalSec} onChange={(e) => setForm({ ...form, scanIntervalSec: Math.max(10, Number(e.target.value) || 0) })} />
                <div className="mt-1 text-xs text-muted">KEV feed refreshes every {form.wildRefreshSec}s</div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={() => save()} loading={saving}><Save className="size-4" /> Save Settings</Button>
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
      <CardHeader title="Add Asset" icon={<Server className="size-4 text-blue-400" />} sub="Generates an asset ID and a one-time enrollment token for the Prohori daemon" />
      <div className="space-y-3 p-4">
        <form onSubmit={enroll} className="flex gap-2">
          <Input placeholder="Display name, e.g. bank-web-03" value={name} onChange={(e) => setName(e.target.value)} />
          <Button type="submit" variant="primary" loading={busy} disabled={!name.trim()}><Plus className="size-4" /> Enroll</Button>
        </form>
        {err && <p className="text-sm text-red-300">{err}</p>}
        {res && (
          <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-950/20 p-3">
            <div className="text-xs font-semibold text-amber-300">This token is shown only once. Copy it now.</div>
            <div className="text-sm">Asset ID: <span className="font-mono text-white">{res.hostId}</span></div>
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

/** Demo: take a lab server's daemon down / bring it back, and watch Sentinel stop proposing for it. */
function OutageControl() {
  const status = usePoll<StatusResponse>("/status", 2000);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useFlash();
  const hosts = status.data?.hosts ?? [];
  const down = hosts.filter((h) => h.health?.state === "unassessable" && h.health.alert);

  async function toggle(id: string, name: string, takeDown: boolean) {
    setBusy(id);
    try {
      await api("/demo/outage", { method: "POST", json: { hostId: id, down: takeDown } });
      setMsg({ ok: true, text: takeDown ? `Daemon on ${name} taken down. Within a few seconds the dashboard shows it cannot be assessed.` : `Daemon on ${name} is starting again; it reports within a few seconds.` });
      refreshAllPolls();
      await status.refresh();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="rounded-lg border border-orange-500/40 bg-bg p-3">
      <div className="flex items-center gap-2">
        <span className="font-display text-sm text-white">Daemon Outage</span>
        {down.length > 0 && <Badge tone="amber" className="uppercase">{down.length} down</Badge>}
      </div>
      <div className="mt-1 text-xs text-muted">Stops a server&apos;s daemon. Sentinel then cannot trust its inventory: it shows an alert and proposes no fixes for that server until the daemon is back.</div>
      <ul className="mt-3 space-y-1.5">
        {hosts.map((h) => {
          const isDown = h.status === "offline";
          return (
            <li key={h.id} className="flex flex-wrap items-center gap-2 rounded-md bg-panel px-3 py-1.5 text-sm">
              <Server className="size-3.5 text-muted" />
              <span className="font-semibold text-white">{h.name}</span>
              <span className={cn("text-xs", isDown ? "text-orange-300" : "text-emerald-300")}>{isDown ? "daemon down" : "daemon online"}</span>
              {h.health?.state === "unassessable" && h.health.alert && <span className="text-xs text-orange-200/80">· Sentinel will not propose fixes</span>}
              <Button className="ml-auto" size="sm" variant={isDown ? "secondary" : "danger"} onClick={() => toggle(h.id, h.name, !isDown)} loading={busy === h.id} disabled={!!busy}>
                <Power className="size-3.5" /> {isDown ? "Bring back" : "Take down"}
              </Button>
            </li>
          );
        })}
        {hosts.length === 0 && <li className="text-xs text-muted">No assets enrolled.</li>}
      </ul>
      <div className="mt-2"><Flash msg={msg} /></div>
    </div>
  );
}

function DemoPanel() {
  const settings = usePoll<Settings>("/settings", 3000);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useFlash();
  const enabled = settings.data?.cveScanEnabled ?? false;

  async function allowScan() {
    setBusy("allow");
    try {
      await api<Settings>("/settings", { method: "PUT", json: { cveScanEnabled: true } });
      setMsg({ ok: true, text: "CVE scanning allowed. A scan is starting now." });
      refreshAllPolls();
      await settings.refresh();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  }

  async function reset() {
    if (!confirm("Reset the demonstration environment? This clears all findings, reports, approvals, chats and the event log, recreates the lab servers and switches CVE scanning off. Scan caches are kept.")) return;
    setBusy("reset");
    try {
      await api<{ ok: boolean }>("/demo/reset", { method: "POST" });
      setMsg({ ok: true, text: "Environment reset. Lab servers are recreating (about 30–45 s). CVE scanning is off." });
      refreshAllPolls();
      await settings.refresh();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card className="border-violet-500/40">
      <CardHeader
        title="Demonstration Controls"
        icon={<FlaskConical className="size-4 text-violet-400" />}
        sub="CVE scanning stays off until you allow it, so nothing is reported before the demo starts"
      />
      <div className="space-y-4 p-4">
        <div className={cn("flex flex-wrap items-center gap-3 rounded-lg border bg-bg p-3", enabled ? "border-violet-500/40" : "border-line")}>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="font-display text-sm text-white">CVE Scanning</span>
              <Badge tone={enabled ? "violet" : "gray"} className="uppercase">{enabled ? "Allowed" : "Off"}</Badge>
            </div>
            <div className="mt-1 text-xs text-muted">Allowing it scans every known CVE against the assets.</div>
          </div>
          <Button variant="danger" onClick={allowScan} loading={busy === "allow"} disabled={!!busy || enabled}>
            <Sparkles className="size-4" /> Allow CVE Scan
          </Button>
        </div>
        <OutageControl />
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" onClick={reset} loading={busy === "reset"} disabled={!!busy}>
            <RotateCcw className="size-4" /> Reset Environment
          </Button>
          <span className="text-xs text-muted">Clears everything, recreates the lab servers and turns CVE scanning off.</span>
        </div>
        <Flash msg={msg} />
        <a href="http://127.0.0.1:8025" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:underline">
          <Mail className="size-4" /> Open Mailbox (Mailpit) · http://127.0.0.1:8025 <ExternalLink className="size-3.5" />
        </a>
      </div>
    </Card>
  );
}

export default function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" icon={<SettingsIcon className="size-6 text-blue-400" />} sub="Report recipients, scan schedule, asset enrollment and demonstration controls" />
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
