"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init ?? {};
  const res = await fetch(`/api${path}`, {
    ...rest,
    headers: { ...(json !== undefined ? { "content-type": "application/json" } : {}), ...(rest.headers ?? {}) },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    cache: "no-store",
  });
  if (res.status === 401 && typeof window !== "undefined") {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    throw new ApiError(401, "unauthorized");
  }
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const errField = data && typeof data === "object" && "error" in data ? (data as { error: unknown }).error : null;
    const msg = errField ? String(errField) : `HTTP ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

export interface Poll<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  updatedAt: number | null;
  refresh: () => Promise<void>;
}

/** Ask every live poll on the page to refresh now (e.g. right after an approve/reject/rollback). */
export function refreshAllPolls() {
  if (typeof window !== "undefined") window.dispatchEvent(new Event("prohori:refresh"));
}

/** Fetch `path` now and every `intervalMs` (default 3 s). Pass null to disable. */
export function usePoll<T>(path: string | null, intervalMs = 3000): Poll<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const pathRef = useRef(path);
  pathRef.current = path;

  const refresh = useCallback(async () => {
    const p = pathRef.current;
    if (!p) return;
    try {
      const d = await api<T>(p);
      if (pathRef.current !== p) return;
      setData(d);
      setError(null);
      setUpdatedAt(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!path) return;
    setLoading(true);
    void refresh();
    if (intervalMs <= 0) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, intervalMs);
    const onRefresh = () => void refresh();
    window.addEventListener("prohori:refresh", onRefresh);
    return () => { clearInterval(t); window.removeEventListener("prohori:refresh", onRefresh); };
  }, [path, intervalMs, refresh]);

  return { data, error, loading, updatedAt, refresh };
}

/** Current time, re-rendered every `tickMs`, for "Xs ago" labels. */
export function useNow(tickMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), tickMs);
    return () => clearInterval(t);
  }, [tickMs]);
  return now;
}
