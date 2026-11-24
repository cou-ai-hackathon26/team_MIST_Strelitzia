// Small helpers shared by Sentinel's AI steps.

/** Run `fn` over `items` with at most `limit` in flight; results keep input order. */
export async function mapPool<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]!, i);
      }
    }),
  );
  return out;
}

/** Reject after `ms` (LLM calls must never hang a scan). */
export function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: Timer;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise<T>((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out after ${Math.round(ms / 1000)}s`)), ms); }),
  ]);
}

/** Compact JSON for prompts / step summaries. */
export function clip(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + `… [${s.length - n} more chars]` : s;
}
