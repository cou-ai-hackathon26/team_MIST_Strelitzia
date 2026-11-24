import { NextResponse } from "next/server";
import { SESSION_COOKIE, SESSION_TTL_MS, adminUsers, brainUrl, checkCredentials, createSessionToken } from "@/lib/session";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  let username = "";
  let password = "";
  try {
    const body = (await req.json()) as { username?: unknown; password?: unknown };
    username = typeof body.username === "string" ? body.username.trim() : "";
    password = typeof body.password === "string" ? body.password : "";
  } catch {
    return NextResponse.json({ error: "invalid body" }, { status: 400 });
  }
  if (adminUsers().size === 0) {
    return NextResponse.json({ error: "No admin accounts configured (set ADMIN_USERS or ADMIN_PASSWORD)" }, { status: 500 });
  }
  if (!(await checkCredentials(username, password))) {
    await new Promise((r) => setTimeout(r, 400));
    return NextResponse.json({ error: "Incorrect username or password" }, { status: 401 });
  }
  // Best-effort audit of the login in the brain's event log; never blocks or fails the login.
  void fetch(`${brainUrl()}/api/audit/login`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${process.env.BRAIN_API_TOKEN ?? ""}`,
      "x-prohori-actor": username,
    },
    body: JSON.stringify({ username }),
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});

  const res = NextResponse.json({ ok: true, username });
  res.cookies.set(SESSION_COOKIE, await createSessionToken(username), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production" && process.env.COOKIE_SECURE === "1",
    path: "/",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
  return res;
}
