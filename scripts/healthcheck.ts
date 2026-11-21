// Pre-flight check for a Prohori demo. Run from the repo root:  bun run healthcheck
// Checks the outside services Sentinel depends on, the local services, and the lab assets.

type Result = { name: string; ok: boolean; detail: string; warn?: boolean };
const results: Result[] = [];
const env = process.env;
const brainUrl = env.BRAIN_URL ?? `http://127.0.0.1:${env.BRAIN_PORT ?? 4400}`;

async function check(name: string, fn: () => Promise<string>, warnOnly = false) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail: `${detail} (${Date.now() - t0} ms)` });
  } catch (e) {
    results.push({ name, ok: false, warn: warnOnly, detail: (e as Error).message });
  }
}

async function fetchOk(url: string, init?: RequestInit, timeoutMs = 20_000): Promise<Response> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res;
}

// ── outside services ──
await check("OSV.dev (vulnerability database)", async () => {
  const res = await fetchOk("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ version: "8.3.6-0maysync1", package: { name: "php8.3", ecosystem: "Ubuntu:24.04:LTS" } }),
  });
  const d = (await res.json()) as { vulns?: { id: string }[] };
  return `${d.vulns?.length ?? 0} matches for the demo PHP build`;
});

await check("CISA KEV (known exploited catalog)", async () => {
  const res = await fetchOk("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const d = (await res.json()) as { count: number; catalogVersion: string };
  return `${d.count} entries, catalog ${d.catalogVersion}`;
});

await check("LLM endpoint (Sentinel's model)", async () => {
  if (!env.OPENCODE_API_KEY || env.OPENCODE_API_KEY.startsWith("your-")) throw new Error("OPENCODE_API_KEY is not set in .env");
  const res = await fetchOk(`${env.LLM_BASE_URL}/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": env.OPENCODE_API_KEY,
      "anthropic-version": "2023-06-01",
      "x-opencode-session": "prohori-healthcheck",
      "User-Agent": env.LLM_USER_AGENT ?? "prohori/0.1",
    },
    body: JSON.stringify({ model: env.LLM_MODEL, max_tokens: 5, messages: [{ role: "user", content: "Reply OK" }] }),
  }, 60_000);
  const d = (await res.json()) as { model?: string };
  return `model ${d.model ?? env.LLM_MODEL} responded`;
});

// ── local services ──
await check("Docker lab assets", async () => {
  const p = Bun.spawnSync(["docker", "ps", "--format", "{{.Names}} {{.Status}}"]);
  if (p.exitCode !== 0) throw new Error("docker is not running or not reachable");
  const lines = p.stdout.toString().split("\n").filter((l) => /prohori-(target-[abc]|mailhog)/.test(l));
  const need = ["target-a", "target-b", "target-c", "mailhog"];
  const missing = need.filter((n) => !lines.some((l) => l.includes(`prohori-${n}`) && /\bUp\b/.test(l)));
  if (missing.length) throw new Error(`not running: ${missing.join(", ")} — run: bun run targets:up`);
  return "target-a, target-b, target-c and Mailpit are up";
});

await check("Lab asset PHP builds", async () => {
  const ver = (c: string) =>
    Bun.spawnSync(["docker", "exec", `prohori-${c}-1`, "dpkg-query", "-W", "-f", "${Version}", "php8.3-common"]).stdout.toString().trim();
  const a = ver("target-a"), b = ver("target-b"), c = ver("target-c");
  const bad: string[] = [];
  if (a !== "8.3.6-0maysync1") bad.push(`bank-web-01 is on ${a || "?"} (expected vulnerable 8.3.6-0maysync1)`);
  if (c !== "8.3.6-0maysync1") bad.push(`bank-batch-01 is on ${c || "?"} (expected vulnerable 8.3.6-0maysync1)`);
  if (!b.includes("ubuntu0.24.04")) bad.push(`bank-web-02 is on ${b || "?"} (expected the patched Ubuntu build)`);
  if (bad.length) throw new Error(`${bad.join("; ")} — use Reset Environment, or run: bun run targets:reset`);
  return `web-01 ${a} · web-02 ${b} · batch-01 ${c}`;
});

await check("Sentinel brain", async () => {
  await fetchOk(`${brainUrl}/health`, undefined, 5_000);
  const res = await fetchOk(`${brainUrl}/api/status`, { headers: { Authorization: `Bearer ${env.BRAIN_API_TOKEN}` } }, 5_000);
  const s = (await res.json()) as {
    hosts: { name: string; status: string }[];
    demo: { replayHeld: string[]; injected: string[]; warning?: string | null };
  };
  const offline = s.hosts.filter((h) => h.status !== "online").map((h) => h.name);
  if (offline.length) throw new Error(`assets offline: ${offline.join(", ")}`);
  if (s.demo.warning) throw new Error(s.demo.warning);
  const state = s.demo.injected.length ? `disclosure already replayed (${s.demo.injected.join(", ")}) — Reset Environment before presenting` : "ready (PHP2Shell embargoed)";
  return `${s.hosts.length} assets online · demo ${state}`;
});

await check("Dashboard", async () => {
  await fetchOk("http://127.0.0.1:3000/login", undefined, 5_000);
  return "http://localhost:3000";
});

await check("Mailpit inbox", async () => {
  await fetchOk("http://127.0.0.1:8025/api/v1/messages", undefined, 5_000);
  return "http://localhost:8025";
}, true);

// ── report ──
const width = Math.max(...results.map((r) => r.name.length));
let failed = 0;
for (const r of results) {
  const mark = r.ok ? "\x1b[32m✓\x1b[0m" : r.warn ? "\x1b[33m!\x1b[0m" : "\x1b[31m✗\x1b[0m";
  if (!r.ok && !r.warn) failed++;
  console.log(`${mark} ${r.name.padEnd(width)}  ${r.detail}`);
}
console.log(failed ? `\n${failed} check(s) failed — see docs/DEMO.md › Troubleshooting.` : "\nAll checks passed. Ready to present.");
process.exit(failed ? 1 : 0);
