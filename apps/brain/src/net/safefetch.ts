// SSRF-safe GET for untrusted URLs (advisory pages an admin pastes, and the links found on them): https only,
// every hop's hostname resolved and checked against private/loopback/link-local ranges, manual redirects (max 5,
// each re-validated), one 15 s budget for the whole chain, text-like content types only, 2 MB body cap.
// No db/env imports so it stays unit-testable.
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export const MAX_REDIRECTS = 5;
export const FETCH_TIMEOUT_MS = 15_000;
export const MAX_BYTES = 2_000_000;
const TEXT_TYPES = /^(text\/(html|plain|xml)|application\/(json|xml|xhtml\+xml|[a-z.+-]+\+(json|xml)))\b/i;

export class SafeFetchError extends Error {
  constructor(msg: string) { super(msg); this.name = "SafeFetchError"; }
}

function v4ToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    n = n * 256 + Number(x);
  }
  return n >>> 0;
}

const V4_BLOCKS: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function v4Blocked(ip: string): boolean {
  const n = v4ToInt(ip);
  if (n === null) return true; // not parseable → refuse
  return V4_BLOCKS.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((v4ToInt(base)! & mask) >>> 0);
  });
}

/** Expand an IPv6 literal to 8 hextets (handles "::" and a trailing dotted IPv4). null if malformed. */
function v6Hextets(ip: string): number[] | null {
  let s = ip.toLowerCase().split("%")[0]!;
  const dotted = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const n = v4ToInt(dotted[2]!);
    if (n === null) return null;
    s = `${dotted[1]}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (h: string) => (h ? h.split(":") : []);
  const head = parse(halves[0]!), tail = halves.length === 2 ? parse(halves[1]!) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const all = [...head, ...Array(fill).fill("0"), ...tail];
  if (all.length !== 8 || all.some((x) => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return all.map((x) => parseInt(x, 16));
}

/** True if the address must never be fetched (loopback, private, link-local, CGNAT, ULA, unspecified, mapped variants…). */
export function isBlockedIp(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, "");
  const fam = isIP(bare);
  if (fam === 4) return v4Blocked(bare);
  if (fam !== 6) return true;
  const h = v6Hextets(bare);
  if (!h) return true;
  if (h.every((x) => x === 0)) return true;                                   // ::
  if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return true;        // ::1
  const embedded = () => `${h[6]! >> 8}.${h[6]! & 255}.${h[7]! >> 8}.${h[7]! & 255}`;
  if (h.slice(0, 5).every((x) => x === 0) && (h[5] === 0xffff || h[5] === 0)) return v4Blocked(embedded()); // ::ffff:a.b.c.d, ::a.b.c.d
  if (h[0] === 0x64 && h[1] === 0xff9b) return v4Blocked(embedded());         // NAT64 64:ff9b::/96
  if (h[0] === 0x2002) return v4Blocked(`${h[1]! >> 8}.${h[1]! & 255}.${h[2]! >> 8}.${h[2]! & 255}`); // 6to4
  if ((h[0]! & 0xfe00) === 0xfc00) return true;                               // ULA fc00::/7
  if ((h[0]! & 0xffc0) === 0xfe80) return true;                               // link-local fe80::/10
  if ((h[0]! & 0xffc0) === 0xfec0) return true;                               // site-local (deprecated)
  if ((h[0]! & 0xff00) === 0xff00) return true;                               // multicast
  return false;
}

/** Validate one URL hop: https, no credentials, hostname resolves only to public addresses. */
export async function assertPublicUrl(raw: string, resolve: typeof lookup = lookup): Promise<URL> {
  let u: URL;
  try { u = new URL(raw); } catch { throw new SafeFetchError(`invalid URL: ${raw.slice(0, 200)}`); }
  if (u.protocol !== "https:") throw new SafeFetchError("only https:// URLs are allowed");
  if (u.username || u.password) throw new SafeFetchError("URLs with credentials are not allowed");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (!host || /^localhost$|\.localhost$|\.local$|\.internal$/i.test(host)) throw new SafeFetchError(`host ${host} is not public`);
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new SafeFetchError(`address ${host} is not public`);
    return u;
  }
  let addrs: { address: string }[];
  try { addrs = await resolve(host, { all: true, verbatim: true }); } catch (e) { throw new SafeFetchError(`cannot resolve ${host}: ${(e as Error).message}`); }
  if (!addrs.length) throw new SafeFetchError(`cannot resolve ${host}`);
  const bad = addrs.find((a) => isBlockedIp(a.address));
  if (bad) throw new SafeFetchError(`host ${host} resolves to a non-public address (${bad.address})`);
  return u;
}

export interface SafeResponse { url: string; status: number; contentType: string; body: string; truncated: boolean }

/**
 * GET an untrusted URL safely. Note: DNS is checked before connecting; a hostile resolver could still rebind between
 * our lookup and fetch's own (accepted residual risk for an admin-initiated, read-only GET).
 */
export async function safeFetch(rawUrl: string, opts: { accept?: string; userAgent?: string } = {}): Promise<SafeResponse> {
  const signal = AbortSignal.timeout(FETCH_TIMEOUT_MS); // one budget for the whole redirect chain
  let url = rawUrl.trim();
  for (let hop = 0; ; hop++) {
    const u = await assertPublicUrl(url);
    const res = await fetch(u, {
      signal, redirect: "manual",
      headers: { "User-Agent": opts.userAgent ?? "prohori-sentinel/0.1 (advisory reader)", Accept: opts.accept ?? "text/html,text/plain;q=0.9,application/json;q=0.8,*/*;q=0.1" },
    });
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      await res.body?.cancel();
      if (hop >= MAX_REDIRECTS) throw new SafeFetchError(`too many redirects (> ${MAX_REDIRECTS})`);
      url = new URL(res.headers.get("location")!, u).toString();
      continue;
    }
    const contentType = res.headers.get("content-type") ?? "";
    if (!TEXT_TYPES.test(contentType.trim())) {
      await res.body?.cancel();
      throw new SafeFetchError(`unsupported content-type "${contentType || "none"}" (text, html, json or xml only)`);
    }
    const { text, truncated } = await readCapped(res, MAX_BYTES);
    return { url: u.toString(), status: res.status, contentType, body: text, truncated };
  }
}

async function readCapped(res: Response, max: number): Promise<{ text: string; truncated: boolean }> {
  if (!res.body) return { text: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0, truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (n + value.length > max) {
      chunks.push(value.subarray(0, max - n));
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    n += value.length;
  }
  return { text: new TextDecoder().decode(Buffer.concat(chunks)), truncated };
}
