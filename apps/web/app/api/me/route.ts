import { readSessionCookie, verifySessionToken } from "@/lib/session";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const username = await verifySessionToken(readSessionCookie(req.headers.get("cookie")));
  if (!username) return Response.json({ error: "unauthorized" }, { status: 401 });
  return Response.json({ username });
}
