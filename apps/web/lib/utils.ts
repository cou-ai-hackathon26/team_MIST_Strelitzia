import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function secondsBetween(iso: string | null | undefined, now: number): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.round((now - t) / 1000);
}

/** "12s ago", "3m ago", "2h ago", "in 33s" */
export function relTime(iso: string | null | undefined, now: number): string {
  const s = secondsBetween(iso, now);
  if (s === null) return "never";
  const abs = Math.abs(s);
  let txt: string;
  if (abs < 5 && s >= 0) return "just now";
  if (abs < 60) txt = `${abs}s`;
  else if (abs < 3600) txt = `${Math.floor(abs / 60)}m`;
  else if (abs < 86400) txt = `${Math.floor(abs / 3600)}h`;
  else txt = `${Math.floor(abs / 86400)}d`;
  return s >= 0 ? `${txt} ago` : `in ${txt}`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-GB", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function fmtDay(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso.length === 10 ? `${iso}T00:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "2-digit", timeZone: "UTC" });
}
