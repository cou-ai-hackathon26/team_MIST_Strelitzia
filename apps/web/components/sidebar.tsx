"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { StatusResponse } from "@prohori/shared";
import { Activity, Bug, CircleUser, CheckSquare, FileText, Globe, LayoutDashboard, LogOut, MessageSquare, Scale, ScrollText, Server, Settings } from "lucide-react";
import { Logo } from "@/components/logo";
import { LiveDot } from "@/components/ui";
import { usePoll } from "@/lib/api";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/findings", label: "Findings", icon: Bug },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/chat", label: "Sentinel", icon: MessageSquare },
  { href: "/judgments", label: "Advisory Judge", icon: Scale },
  { href: "/approvals", label: "Approvals", icon: CheckSquare },
  { href: "/wild", label: "Threat Intelligence", icon: Globe },
  { href: "/events", label: "Audit Log", icon: ScrollText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { data, error } = usePoll<StatusResponse>("/status", 5000);
  const [me, setMe] = useState<string | null>(null);
  useEffect(() => {
    fetch("/api/me").then((r) => (r.ok ? r.json() : null)).then((d: { username?: string } | null) => setMe(d?.username ?? null)).catch(() => {});
  }, []);
  const exposed = data?.totals.exposed ?? 0;
  const pending = data?.pendingActions ?? 0;

  async function logout() {
    await fetch("/api/logout", { method: "POST" });
    window.location.href = "/login";
  }

  return (
    <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-line bg-[#0c1016]">
      <div className="px-4 py-5">
        <Logo />
      </div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          const count = href === "/findings" ? exposed : href === "/approvals" ? pending : 0;
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
                active ? "bg-blue-500/12 font-medium text-white ring-1 ring-blue-500/30" : "text-muted hover:bg-panel-2 hover:text-fg",
              )}
            >
              <Icon className={cn("size-4", active ? "text-blue-400" : "")} />
              <span className="flex-1">{label}</span>
              {count > 0 && (
                <span className={cn("rounded-full px-1.5 text-[11px] font-bold", href === "/findings" ? "bg-red-600 text-white" : "bg-amber-500 text-black")}>
                  {count}
                </span>
              )}
            </Link>
          );
        })}
        {data && data.hosts.length > 0 && (
          <div className="pt-5">
            <div className="px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-dim">Assets</div>
            {data.hosts.map((h) => {
              const active = pathname === `/hosts/${h.id}`;
              return (
                <Link
                  key={h.id}
                  href={`/hosts/${h.id}`}
                  className={cn("flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-sm", active ? "bg-panel-2 text-white" : "text-muted hover:bg-panel-2 hover:text-fg")}
                >
                  <Server className="size-3.5" />
                  <span className="flex-1 truncate">{h.name}</span>
                  {h.findingCounts.exposed > 0 ? (
                    <span className="size-2 rounded-full bg-exposed" title="Exposed" />
                  ) : (
                    <span className={cn("size-2 rounded-full", h.status === "online" ? "bg-emerald-500/70" : "bg-slate-600")} />
                  )}
                </Link>
              );
            })}
          </div>
        )}
      </nav>
      <div className="space-y-2 border-t border-line p-3">
        <div className="flex items-center gap-2 px-1 text-xs text-muted">
          <Activity className="size-3.5" />
          <span className="flex-1">Sentinel</span>
          <LiveDot ok={!error && !!data} />
          <span className={error ? "text-red-300" : "text-emerald-300"}>{error ? "Offline" : data ? "Connected" : "…"}</span>
        </div>
        <div className="flex items-center gap-2 rounded-lg bg-panel-2/60 px-2 py-1.5">
          <CircleUser className="size-4 text-blue-300" />
          <div className="min-w-0 flex-1 leading-tight">
            <div className="truncate text-sm font-medium text-fg">{me ?? "…"}</div>
            <div className="text-[10px] text-dim">Administrator</div>
          </div>
          <button onClick={logout} title="Sign out" className="flex items-center gap-1 rounded-md px-1.5 py-1 text-xs text-muted hover:bg-panel hover:text-fg">
            <LogOut className="size-3.5" /> Sign out
          </button>
        </div>
      </div>
    </aside>
  );
}
