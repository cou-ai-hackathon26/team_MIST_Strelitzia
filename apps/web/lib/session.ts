// Signed admin session cookie: "<base64url(username)>.<expiresAtMs>.<hex hmac-sha256(user.exp)>".
// Uses Web Crypto so it works in both the proxy and route handlers.

export const SESSION_COOKIE = "prohori_session";
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const enc = new TextEncoder();

function secret(): string {
  return process.env.SESSION_SECRET || "prohori-dev-insecure-secret";
}

async function hmacHex(data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret()), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

const b64u = (s: string) => btoa(String.fromCharCode(...enc.encode(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));

/** Admin accounts from ADMIN_USERS="zamil:pw,nusrat:pw"; falls back to "admin" / ADMIN_PASSWORD. */
export function adminUsers(): Map<string, string> {
  const users = new Map<string, string>();
  for (const entry of (process.env.ADMIN_USERS ?? "").split(",")) {
    const i = entry.indexOf(":");
    if (i <= 0) continue;
    const u = entry.slice(0, i).trim();
    const p = entry.slice(i + 1).trim();
    if (u && p) users.set(u, p);
  }
  if (users.size === 0 && process.env.ADMIN_PASSWORD) users.set("admin", process.env.ADMIN_PASSWORD);
  return users;
}

export async function createSessionToken(username: string): Promise<string> {
  const payload = `${b64u(username)}.${Date.now() + SESSION_TTL_MS}`;
  return `${payload}.${await hmacHex(payload)}`;
}

/** Returns the username for a valid, unexpired token, else null. */
export async function verifySessionToken(token: string | undefined | null): Promise<string | null> {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [u, exp, sig] = parts as [string, string, string];
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return null;
  if (!safeEqual(sig, await hmacHex(`${u}.${exp}`))) return null;
  try {
    return unb64u(u);
  } catch {
    return null;
  }
}

export async function checkCredentials(username: string, password: string): Promise<boolean> {
  const expected = adminUsers().get(username);
  // Always do the HMAC work so timing doesn't reveal which usernames exist.
  const a = await hmacHex(`pw:${password}`);
  const b = await hmacHex(`pw:${expected ?? "\u0000no-such-user"}`);
  return expected !== undefined && safeEqual(a, b);
}

export function readSessionCookie(cookieHeader: string | null): string | undefined {
  return (cookieHeader ?? "")
    .split(/;\s*/)
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`))
    ?.slice(SESSION_COOKIE.length + 1);
}

export function brainUrl(): string {
  return (process.env.BRAIN_URL || "http://127.0.0.1:4400").replace(/\/+$/, "");
}
