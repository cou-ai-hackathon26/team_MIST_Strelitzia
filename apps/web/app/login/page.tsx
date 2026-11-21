"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Lock } from "lucide-react";
import { Logo } from "@/components/logo";
import { Button, Card, Input } from "@/components/ui";

function LoginForm() {
  const params = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const d = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(d.error || `HTTP ${res.status}`);
      }
      const next = params.get("next");
      window.location.href = next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  return (
    <Card className="w-full max-w-sm p-6 shadow-2xl shadow-black/40">
      <div className="mb-6">
        <Logo />
      </div>
      <h1 className="text-lg font-semibold">Admin sign in</h1>
      <p className="mt-1 text-sm text-muted">Security operations dashboard</p>
      <form onSubmit={submit} className="mt-5 space-y-3">
        <label className="block text-xs font-medium text-muted" htmlFor="user">Username</label>
        <Input id="user" autoFocus autoComplete="username" placeholder="e.g. rahim" value={username} onChange={(e) => setUsername(e.target.value)} />
        <label className="block text-xs font-medium text-muted" htmlFor="pw">Password</label>
        <Input id="pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <p className="text-sm text-red-400">{error}</p>}
        <Button type="submit" variant="primary" className="w-full" loading={busy} disabled={!password || !username}>
          <Lock className="size-4" /> Sign in
        </Button>
      </form>
    </Card>
  );
}

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,#132036_0%,#0a0d12_60%)] p-4">
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
