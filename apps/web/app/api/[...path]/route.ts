import { brainUrl, readSessionCookie, verifySessionToken } from "@/lib/session";

// Proxies /api/* to the brain, adding the bearer token. The response body is passed through
// as a stream (no buffering) so /api/chat's SSE UI message stream reaches the browser live.
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding",
  "upgrade", "proxy-connection", "te", "trailer",
]);

async function handle(req: Request, ctx: { params: Promise<{ path: string[] }> }): Promise<Response> {
  // Defense in depth (the proxy already checks this).
  const actor = await verifySessionToken(readSessionCookie(req.headers.get("cookie")));
  if (!actor) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }

  const brain = brainUrl();
  const { path } = await ctx.params;
  const search = new URL(req.url).search;
  const target = `${brain}/api/${path.map(encodeURIComponent).join("/")}${search}`;

  const headers = new Headers();
  const ct = req.headers.get("content-type");
  if (ct) headers.set("content-type", ct);
  headers.set("accept", req.headers.get("accept") ?? "*/*");
  headers.set("authorization", `Bearer ${process.env.BRAIN_API_TOKEN ?? ""}`);
  // Who is acting: the brain records it on audit events and action decisions. Never taken from the client.
  headers.set("x-prohori-actor", actor);

  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: req.method,
      headers,
      body: hasBody ? await req.arrayBuffer() : undefined,
      signal: req.signal,
      cache: "no-store",
      redirect: "manual",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return Response.json({ error: `Sentinel unreachable at ${brain}: ${msg}` }, { status: 502 });
  }

  const out = new Headers();
  upstream.headers.forEach((v, k) => {
    if (!HOP_BY_HOP.has(k.toLowerCase())) out.set(k, v);
  });
  out.set("cache-control", "no-cache, no-transform");
  out.set("x-accel-buffering", "no");

  return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const PATCH = handle;
export const DELETE = handle;
