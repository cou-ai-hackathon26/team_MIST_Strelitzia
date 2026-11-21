import * as React from "react";
import type { FindingStatus, Priority } from "@prohori/shared";
import { AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export function Card({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-line bg-panel", className)} {...p} />;
}

export function CardHeader({ title, icon, right, className, sub }: { title: React.ReactNode; icon?: React.ReactNode; right?: React.ReactNode; className?: string; sub?: React.ReactNode }) {
  return (
    <div className={cn("flex items-center justify-between gap-3 border-b border-line px-4 py-3", className)}>
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-sm font-semibold text-fg">
          {icon}
          {title}
        </div>
        {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
      </div>
      {right}
    </div>
  );
}

type Variant = "primary" | "secondary" | "ghost" | "danger" | "success" | "warning";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-white hover:bg-blue-500 border-transparent",
  secondary: "bg-panel-2 text-fg border-line-2 hover:bg-[#1c2430]",
  ghost: "bg-transparent text-muted border-transparent hover:bg-panel-2 hover:text-fg",
  danger: "bg-red-600/90 text-white border-transparent hover:bg-red-500",
  success: "bg-emerald-600 text-white border-transparent hover:bg-emerald-500",
  warning: "bg-amber-500/15 text-amber-300 border-amber-500/40 hover:bg-amber-500/25",
};

export function Button({
  variant = "secondary", size = "md", loading, className, children, disabled, ...p
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md" | "lg"; loading?: boolean }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
        size === "sm" && "h-7 px-2.5 text-xs",
        size === "md" && "h-9 px-3.5 text-sm",
        size === "lg" && "h-11 px-5 text-base",
        VARIANTS[variant],
        className,
      )}
      disabled={disabled || loading}
      {...p}
    >
      {loading && <Loader2 className="size-3.5 animate-spin" />}
      {children}
    </button>
  );
}

export function Input({ className, ...p }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-lg border border-line-2 bg-bg px-3 text-sm text-fg placeholder:text-dim focus:border-accent focus:outline-none",
        className,
      )}
      {...p}
    />
  );
}

type Tone = "red" | "amber" | "green" | "blue" | "gray" | "violet";
const TONES: Record<Tone, string> = {
  red: "bg-red-500/15 text-red-300 border-red-500/40",
  amber: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  green: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  blue: "bg-blue-500/15 text-blue-300 border-blue-500/40",
  gray: "bg-slate-500/10 text-slate-300 border-slate-500/30",
  violet: "bg-violet-500/15 text-violet-300 border-violet-500/40",
};

export function Badge({ tone = "gray", className, ...p }: React.HTMLAttributes<HTMLSpanElement> & { tone?: Tone }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-0.5 text-[11px] font-semibold leading-none tracking-wide", TONES[tone], className)}
      {...p}
    />
  );
}

export const STATUS_META: Record<FindingStatus, { label: string; short: string; tone: Tone; dot: string; text: string }> = {
  exposed: { label: "Exposed", short: "EXPOSED", tone: "red", dot: "bg-exposed", text: "text-red-400" },
  vulnerable_not_exposed: { label: "Vulnerable, not exposed", short: "NOT EXPOSED", tone: "amber", dot: "bg-vne", text: "text-amber-400" },
  not_affected: { label: "Not affected", short: "SAFE", tone: "green", dot: "bg-safe", text: "text-emerald-400" },
};

export function StatusPill({ status, size = "md", className }: { status: FindingStatus; size?: "md" | "lg"; className?: string }) {
  const m = STATUS_META[status];
  return (
    <Badge tone={m.tone} className={cn(size === "lg" && "px-2 py-1 text-xs", "uppercase", className)}>
      <span className={cn("size-1.5 rounded-full", m.dot)} />
      {m.label}
    </Badge>
  );
}

const PRIORITY_TONE: Record<Priority, Tone> = { critical: "red", high: "red", medium: "amber", low: "blue", info: "gray" };
export function PriorityBadge({ priority }: { priority: Priority }) {
  return (
    <Badge tone={PRIORITY_TONE[priority]} className={cn("uppercase", priority === "critical" && "bg-red-600 text-white border-red-500")}>
      {priority}
    </Badge>
  );
}

export function KevBadge({ className }: { className?: string }) {
  return (
    <Badge tone="red" className={cn("border-red-500/60 bg-red-950/60 text-red-200", className)} title="Listed in CISA Known Exploited Vulnerabilities catalog — exploited in the wild">
      KEV · EXPLOITED
    </Badge>
  );
}

export function LiveDot({ ok = true, className }: { ok?: boolean; className?: string }) {
  return (
    <span className={cn("relative inline-flex size-2", className)}>
      {ok && <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-50" />}
      <span className={cn("relative inline-flex size-2 rounded-full", ok ? "bg-emerald-400" : "bg-slate-500")} />
    </span>
  );
}

export function PageHeader({ title, sub, right, icon }: { title: React.ReactNode; sub?: React.ReactNode; right?: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="flex items-center gap-2.5 text-2xl font-semibold tracking-tight text-fg">
          {icon}
          {title}
        </h1>
        {sub && <p className="mt-1 text-sm text-muted">{sub}</p>}
      </div>
      {right && <div className="flex items-center gap-2">{right}</div>}
    </div>
  );
}

export function LiveTag({ updatedAt, error, now }: { updatedAt: number | null; error: string | null; now: number }) {
  const age = updatedAt ? Math.max(0, Math.round((now - updatedAt) / 1000)) : null;
  const ok = !error && age !== null && age < 10;
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-line bg-panel px-2.5 py-1 text-xs text-muted">
      <LiveDot ok={ok} />
      {error ? <span className="text-red-300">Sentinel offline</span> : ok ? <span className="text-emerald-300">LIVE</span> : "connecting…"}
      {age !== null && !error && <span className="text-dim">· {age}s</span>}
    </span>
  );
}

export function ErrorBanner({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return (
    <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-sm text-red-200">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <span>{error}</span>
    </div>
  );
}

export function Empty({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("rounded-xl border border-dashed border-line-2 px-4 py-10 text-center text-sm text-muted", className)}>{children}</div>;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-lg bg-panel-2", className)} />;
}

export function Mono({ className, ...p }: React.HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("font-mono text-[0.85em]", className)} {...p} />;
}

export function KV({ k, v, mono = true }: { k: React.ReactNode; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[minmax(0,11rem)_1fr] gap-3 border-b border-line/60 py-1.5 text-sm last:border-0">
      <div className="truncate text-muted">{k}</div>
      <div className={cn("min-w-0 break-words text-fg", mono && "font-mono text-[0.8rem]")}>{v}</div>
    </div>
  );
}
