// Mock Prohori brain for developing/verifying the dashboard without apps/brain.
// Run: bun apps/web/scripts/mock-brain.ts   (port 4100; set BRAIN_URL=http://127.0.0.1:4100 for the web app)
// Serves contract-shaped fixtures for every GET route, accepts the POST/PUT routes,
// and streams a fake AI SDK UI-message SSE for /api/chat (one tool call + text).

import { createUIMessageStream, createUIMessageStreamResponse } from "ai";
import type {
  ActionRecord, AuditEvent, EnrollResponse, Finding, FindingStatus, HostDetailResponse, HostSummary,
  InventorySnapshot, Report, ScanState, Settings, StatusResponse, WildCve,
} from "@prohori/shared";

const PORT = Number(process.env.MOCK_BRAIN_PORT ?? 4100);
const TOKEN = process.env.BRAIN_API_TOKEN; // if set, enforce like the real brain

const iso = (offsetSec = 0) => new Date(Date.now() + offsetSec * 1000).toISOString();
let seq = 0;
const id = (p: string) => `${p}-${(++seq).toString(36)}${Math.random().toString(36).slice(2, 6)}`;

const PHP2SHELL = ["CVE-2026-109618", "CVE-2026-109619"];

// ---------------- state ----------------
const settings: Settings = { reportEmails: ["it-team@bank.example"], scanIntervalSec: 45, wildRefreshSec: 900, tier2Enabled: true };
const demo = { replayHeld: [] as string[], injected: [...PHP2SHELL] };
const scan: ScanState = {
  running: false,
  lastStartedAt: iso(-20),
  lastFinishedAt: iso(-12),
  nextRunAt: iso(33),
  lastResult: { newFindings: 6, changedFindings: 0, reportsSent: 1 },
};

function pkgs(phpVer: string, sapis: string[], web: boolean): InventorySnapshot["packages"] {
  const base = [
    { name: "openssl", version: "3.0.13-0ubuntu3.6", source: "openssl", arch: "amd64" },
    { name: "libc6", version: "2.39-0ubuntu8.6", source: "glibc", arch: "amd64" },
    { name: "bash", version: "5.2.21-2ubuntu4", source: "bash", arch: "amd64" },
    { name: "osquery", version: "5.14.1-1.linux", source: "osquery", arch: "amd64" },
    { name: "php8.3-common", version: phpVer, source: "php8.3", arch: "amd64" },
    { name: "php8.3-cli", version: phpVer, source: "php8.3", arch: "amd64" },
  ];
  for (const s of sapis) base.push({ name: `php8.3-${s}`, version: phpVer, source: "php8.3", arch: "amd64" });
  if (web) base.push({ name: "nginx", version: "1.24.0-2ubuntu7.4", source: "nginx", arch: "amd64" });
  return base;
}

function inventory(hostname: string, phpVer: string, web: boolean): InventorySnapshot {
  return {
    collectedAt: iso(-40),
    hostname,
    os: { name: "Ubuntu", version: "24.04.3 LTS (Noble Numbat)", versionId: "24.04", codename: "noble", platform: "ubuntu" },
    packages: pkgs(phpVer, web ? ["fpm"] : [], web),
    listeningPorts: web
      ? [
          { port: 80, protocol: "tcp", address: "0.0.0.0", process: "nginx", pid: 101 },
          { port: 9000, protocol: "tcp", address: "127.0.0.1", process: "php-fpm8.3", pid: 120 },
        ]
      : [],
    processes: web
      ? [{ name: "nginx", path: "/usr/sbin/nginx", pid: 101 }, { name: "php-fpm8.3", path: "/usr/sbin/php-fpm8.3", pid: 120 }]
      : [{ name: "cron", path: "/usr/sbin/cron", pid: 50 }],
    firewall: { available: true, closedPorts: [] },
    config: web
      ? {
          "/etc/php/8.3/fpm/php.ini:memory_limit": "128M",
          "/etc/php/8.3/fpm/php.ini:post_max_size": "8M",
          "/etc/php/8.3/fpm/php.ini:upload_max_filesize": "2M",
          "/etc/php/8.3/fpm/php.ini:file_uploads": "On",
          "/etc/nginx/nginx.conf:client_max_body_size": "1m",
        }
      : { "/etc/php/8.3/cli/php.ini:memory_limit": "-1", "/etc/php/8.3/cli/php.ini:file_uploads": "On" },
  };
}

const hosts: HostSummary[] = [
  { id: "web-a", name: "bank-web-01", status: "online", lastSeen: iso(-4), os: "Ubuntu 24.04.3 LTS", daemonVersion: "0.1.0", tier2Enabled: true, findingCounts: { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 }, rawMatchCount: 56 },
  { id: "web-b", name: "bank-web-02", status: "online", lastSeen: iso(-7), os: "Ubuntu 24.04.3 LTS", daemonVersion: "0.1.0", tier2Enabled: true, findingCounts: { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 }, rawMatchCount: 1 },
  { id: "batch-c", name: "bank-batch-01", status: "online", lastSeen: iso(-2), os: "Ubuntu 24.04.3 LTS", daemonVersion: "0.1.0", tier2Enabled: false, findingCounts: { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 }, rawMatchCount: 56 },
];
const inventories: Record<string, InventorySnapshot> = {
  "web-a": inventory("bank-web-01", "8.3.6-0maysync1", true),
  "web-b": inventory("bank-web-02", "8.3.6-0ubuntu0.24.04.13", true),
  "batch-c": inventory("bank-batch-01", "8.3.6-0maysync1", false),
};

const RATIONALE: Record<FindingStatus, string> = {
  exposed: `**bank-web-01 is exposed and this is an emergency.**

- Installed \`php8.3-fpm\` build is \`8.3.6-0maysync1\` from the noble *release* pocket. OSV (Ubuntu:24.04:LTS, source \`php8.3\`) lists this build as affected by **UBUNTU-CVE-2026-109618**; the first fixed build is \`8.3.6-0ubuntu0.24.04.13\`.
- \`nginx\` listens on **0.0.0.0:80** and passes \`.php\` requests to php-fpm; an upload form exists at \`/upload.php\`, so a remote attacker can reach the vulnerable multipart parser.
- The CVE is on **CISA KEV** (exploited in the wild).

Upgrade is the only complete fix. php.ini changes only reduce the attack surface.`,
  vulnerable_not_exposed: `**bank-batch-01 has the vulnerable build but no network path to it.**

- Installed \`php8.3-cli\` \`8.3.6-0maysync1\` is affected (same as bank-web-01).
- Only the CLI SAPI is installed; **no web server and no listening sockets** were found by osquery, so the multipart parser is not reachable remotely.

Upgrade at normal priority (next maintenance window).`,
  not_affected: `**bank-web-02 is not affected — despite the same "PHP 8.3.6" banner.**

- Installed build is \`8.3.6-0ubuntu0.24.04.13\` from *noble-security*. Ubuntu **backported** the PHP2Shell fix into this build without changing the upstream version number.
- OSV returns no PHP2Shell vulnerabilities for this exact build.

A version-number scanner flags it because \`8.3.6 < 8.3.36\`; that is a false positive.`,
};

function mkFinding(hostId: string, cve: string, status: FindingStatus, installed: string, reportId: string | null): Finding {
  const exposed = status === "exposed";
  return {
    id: `f-${hostId}-${cve.slice(-6)}`,
    hostId,
    cveId: cve,
    aliases: [`UBUNTU-${cve}`],
    title: cve.endsWith("618") ? "PHP2Shell: RCE via OOM corruption in multipart parsing" : "PHP2Shell: heap corruption in input nesting handling",
    status,
    priority: exposed ? "critical" : status === "vulnerable_not_exposed" ? "medium" : "info",
    confidence: "high",
    needsConfirmation: false,
    inKev: true,
    cvss: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    package: { name: "php8.3", installedVersion: installed, fixedVersion: "8.3.6-0ubuntu0.24.04.13" },
    naiveVerdict: "vulnerable",
    rationale: RATIONALE[status],
    mitigations:
      status === "not_affected"
        ? []
        : [
            "Upgrade `php8.3` packages to `8.3.6-0ubuntu0.24.04.13` or later (`apt-get install --only-upgrade php8.3-fpm php8.3-cli php8.3-common`). **This is the only complete fix.**",
            ...(exposed
              ? [
                  "Partial: block `multipart/form-data` at nginx if uploads are not needed (breaks /upload.php).",
                  "Partial: lower `post_max_size` and `max_input_nesting_level` in the FPM php.ini.",
                  "Partial (incomplete): `memory_limit=-1` does not prevent exploitation on its own.",
                ]
              : []),
          ],
    evidence:
      status === "exposed"
        ? { installed: "php8.3-fpm 8.3.6-0maysync1 (noble release)", listening: "0.0.0.0:80 nginx → php-fpm8.3", upload_form: "/upload.php", osv: "UBUNTU-CVE-2026-109618 affected" }
        : status === "vulnerable_not_exposed"
          ? { installed: "php8.3-cli 8.3.6-0maysync1", listening: "no listening sockets", web_server: "none installed" }
          : { installed: "php8.3-fpm 8.3.6-0ubuntu0.24.04.13 (noble-security)", listening: "0.0.0.0:80 nginx", osv: "no PHP2Shell vulns for this build" },
    firstSeen: iso(-300),
    updatedAt: iso(-12),
    reportId,
  };
}

let findings: Finding[] = [];
let reports: Report[] = [];
let actions: ActionRecord[] = [];
const audit: AuditEvent[] = [];
const threads = new Map<string, unknown[]>(); // threadId -> UIMessage[]

function log(kind: AuditEvent["kind"], message: string, extra: Partial<AuditEvent> & { actor?: string; ago?: number } = {}) {
  const { ago, ...rest } = extra;
  audit.unshift({ id: id("ev"), at: iso(-(ago ?? 0)), kind, message, actor: "prohori", ...rest });
  audit.sort((a, b) => b.at.localeCompare(a.at));
  if (audit.length > 400) audit.pop();
}

function baseAction(over: Partial<ActionRecord> & Pick<ActionRecord, "id" | "type" | "params" | "reason">): ActionRecord {
  return {
    hostId: "web-a",
    findingId: findings[0]?.id ?? null,
    state: "pending",
    proposedBy: "agent",
    createdAt: iso(),
    decidedAt: null,
    decidedBy: null,
    decisionNote: null,
    threadId: null,
    supersedes: null,
    supersededBy: null,
    rolledBackBy: null,
    result: null,
    ...over,
  };
}

function seedFindings() {
  const rid = "r-php2shell";
  findings = PHP2SHELL.flatMap((cve) => [
    mkFinding("web-a", cve, "exposed", "8.3.6-0maysync1", rid),
    mkFinding("web-b", cve, "not_affected", "8.3.6-0ubuntu0.24.04.13", rid),
    mkFinding("batch-c", cve, "vulnerable_not_exposed", "8.3.6-0maysync1", rid),
  ]);
  reports = [
    {
      id: rid,
      createdAt: iso(-11),
      title: "PHP2Shell (CVE-2026-109618/109619): bank-web-01 EXPOSED — emergency upgrade required",
      findingIds: findings.map((f) => f.id),
      markdown: `# PHP2Shell exposure report

**Summary:** 1 of 3 servers is exposed. A version-number scanner would flag all 3.

| Server | PHP build | Verdict | Action |
|---|---|---|---|
| bank-web-01 | 8.3.6-0maysync1 | **EXPOSED** (KEV) | Upgrade now |
| bank-batch-01 | 8.3.6-0maysync1 | vulnerable, not exposed | Upgrade, normal priority |
| bank-web-02 | 8.3.6-0ubuntu0.24.04.13 | not affected | none |

## bank-web-01
${RATIONALE.exposed}

## bank-batch-01
${RATIONALE.vulnerable_not_exposed}

## bank-web-02
${RATIONALE.not_affected}

> Upgrade is the only complete fix. Partial mitigations (blocking multipart, lowering input limits) are interim only.
`,
      emailedTo: [...settings.reportEmails],
      emailedAt: iso(-10),
    },
  ];

  reports.push({
    id: "r-baseline",
    createdAt: iso(-86400),
    title: "Weekly baseline: no exposed servers",
    findingIds: [],
    markdown: "# Weekly baseline\n\nNo server is exposed to a known-exploited vulnerability. 3 hosts online.",
    emailedTo: ["it-team@bank.example"],
    emailedAt: iso(-86390),
  });
  actions = [
    // A superseded + revised pair: the agent first proposed blocking multipart, then revised to closing port 80 in chat.
    baseAction({
      id: "a-block-web-a",
      type: "nginx_block_multipart",
      params: {},
      reason: "Interim partial mitigation: reject multipart uploads at nginx until the upgrade is applied.",
      state: "superseded",
      createdAt: iso(-400),
      threadId: "t-demo-review",
      supersededBy: "a-fw-web-a",
    }),
    baseAction({
      id: "a-fw-web-a",
      type: "firewall_port",
      params: { port: 80, protocol: "tcp", state: "closed" },
      reason: "Containment: bank-web-01 is exposed to PHP2Shell (KEV) via nginx on 0.0.0.0:80. Closing 80/tcp removes the network path immediately while the upgrade is scheduled. (Revised from the multipart block after discussion: multipart blocking is only partial.)",
      createdAt: iso(-380),
      threadId: "t-demo-review",
      supersedes: "a-block-web-a",
    }),
    baseAction({
      id: "a-upgrade-web-a",
      type: "upgrade_packages",
      params: { packages: ["php8.3-fpm", "php8.3-cli", "php8.3-common"] },
      reason: "bank-web-01 is exposed to PHP2Shell (KEV). Upgrading php8.3 to the noble-security build 8.3.6-0ubuntu0.24.04.13 is the only complete fix.",
      createdAt: iso(-370),
    }),
    baseAction({
      id: "a-restart-batch-c",
      hostId: "batch-c",
      findingId: findings[2]?.id ?? null,
      type: "set_php_directive",
      params: { sapi: "cli", directive: "memory_limit", value: "256M" },
      reason: "Partial: cap CLI memory on bank-batch-01.",
      state: "rejected",
      createdAt: iso(-3000),
      decidedAt: iso(-2900),
      decidedBy: "nusrat",
      decisionNote: "Not needed — no network path; we'll upgrade in the maintenance window.",
    }),
  ];
  threads.set("t-demo-review", [
    { id: "m-1", role: "user", parts: [{ type: "text", text: "Can we avoid breaking uploads? Is blocking multipart enough?" }] },
    {
      id: "m-2",
      role: "assistant",
      parts: [
        { type: "dynamic-tool", toolName: "reviseProposal", toolCallId: "call-rev1", state: "output-available", input: { actionId: "a-block-web-a", type: "firewall_port", params: { port: 80, protocol: "tcp", state: "closed" } }, output: actions[1] },
        { type: "text", text: "Blocking multipart is only a **partial** mitigation. I revised the proposal to close **80/tcp** (containment) until the upgrade is applied. The site goes offline; upgrade is the complete fix." },
      ],
    },
  ]);
}

function recount() {
  for (const h of hosts) {
    h.lastSeen = iso(-Math.floor(Math.random() * 8));
    h.findingCounts = { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 };
    for (const f of findings) if (f.hostId === h.id) h.findingCounts[f.status]++;
  }
}

seedFindings();
// Events of every kind, oldest first (ago = seconds in the past).
log("login", "nusrat signed in", { actor: "nusrat", ago: 3100 });
log("action_rejected", "nusrat rejected set_php_directive on bank-batch-01", { actor: "nusrat", hostId: "batch-c", ago: 2900, data: { actionId: "a-restart-batch-c", note: "Not needed — no network path; we'll upgrade in the maintenance window." } });
log("host_online", "bank-web-01 connected", { actor: "daemon:web-a", hostId: "web-a", ago: 900 });
log("host_online", "bank-web-02 connected", { actor: "daemon:web-b", hostId: "web-b", ago: 899 });
log("host_online", "bank-batch-01 connected", { actor: "daemon:batch-c", hostId: "batch-c", ago: 898 });
log("host_offline", "bank-batch-01 missed heartbeats", { actor: "prohori", hostId: "batch-c", ago: 860 });
log("host_online", "bank-batch-01 reconnected", { actor: "daemon:batch-c", hostId: "batch-c", ago: 850 });
log("inventory_changed", "bank-web-01 inventory changed: 1 package updated", { actor: "daemon:web-a", hostId: "web-a", ago: 840 });
log("wild_refreshed", "CISA KEV refreshed: 2 new entries", { ago: 800 });
log("settings_changed", "rahim changed scan interval to 45s", { actor: "rahim", ago: 700, data: { scanIntervalSec: 45 } });
log("demo_inject", "rahim released PHP2Shell for replay (Oct 21 disclosure)", { actor: "rahim", cveId: PHP2SHELL[0], ago: 600 });
log("scan_started", "Scheduled scan started", { ago: 560 });
log("cve_discovered", "New CVE relevant to our inventory: CVE-2026-109618 (PHP2Shell, KEV)", { cveId: PHP2SHELL[0], ago: 555 });
log("cve_discovered", "New CVE relevant to our inventory: CVE-2026-109619 (PHP2Shell, KEV)", { cveId: PHP2SHELL[1], ago: 554 });
log("vulnerable_detected", "bank-web-01 is EXPOSED to CVE-2026-109618 (critical, KEV)", { hostId: "web-a", cveId: PHP2SHELL[0], ago: 550 });
log("vulnerable_detected", "bank-batch-01 is vulnerable but not exposed to CVE-2026-109618", { hostId: "batch-c", cveId: PHP2SHELL[0], ago: 549 });
log("finding_new", "CVE-2026-109618 on bank-web-02: not affected (patched build)", { hostId: "web-b", cveId: PHP2SHELL[0], ago: 548 });
log("scan_finished", "Scan finished: 6 new findings", { ago: 540, data: { newFindings: 6 } });
log("report_generated", "Report generated: PHP2Shell exposure (1 exposed, 1 vulnerable, 1 safe)", { ago: 530, data: { reportId: "r-php2shell" } });
log("report_sent", "Report emailed", { ago: 528, data: { reportId: "r-php2shell", recipients: ["it-team@bank.example"] } });
log("login", "rahim signed in", { actor: "rahim", ago: 450 });
log("action_proposed", "Prohori proposed nginx_block_multipart on bank-web-01", { hostId: "web-a", ago: 400, data: { actionId: "a-block-web-a" } });
log("action_revised", "Prohori revised the proposal: close port 80/tcp instead of blocking multipart", { hostId: "web-a", ago: 380, data: { actionId: "a-fw-web-a", supersedes: "a-block-web-a", threadId: "t-demo-review" } });
log("action_proposed", "Prohori proposed upgrade_packages on bank-web-01", { hostId: "web-a", ago: 370, data: { actionId: "a-upgrade-web-a" } });
log("error", "OSV query timed out once (retried OK)", { ago: 300 });

const wildList: WildCve[] = [];
const wild: WildCve[] = [
  { cveId: "CVE-2026-109618", vendorProject: "PHP Group", product: "PHP", name: "PHP2Shell Remote Code Execution Vulnerability", dateAdded: "2026-10-22", shortDescription: "PHP contains a memory corruption vulnerability in multipart/form-data parsing that can be triggered by an out-of-memory condition, allowing remote code execution.", knownRansomwareCampaignUse: "Known", dueDate: "2026-11-12", affectsHosts: ["web-a", "batch-c"] },
  { cveId: "CVE-2026-109619", vendorProject: "PHP Group", product: "PHP", name: "PHP2Shell Heap Corruption Vulnerability", dateAdded: "2026-10-22", shortDescription: "PHP contains a heap corruption vulnerability in input nesting handling, chained with CVE-2026-109618 for remote code execution.", knownRansomwareCampaignUse: "Unknown", dueDate: "2026-11-12", affectsHosts: ["web-a", "batch-c"] },
  { cveId: "CVE-2026-20431", vendorProject: "Fortinet", product: "FortiOS", name: "Fortinet FortiOS SSL-VPN Heap Overflow", dateAdded: "2026-11-10", shortDescription: "FortiOS SSL-VPN contains a heap-based buffer overflow that allows unauthenticated remote code execution.", knownRansomwareCampaignUse: "Known", dueDate: "2026-12-01", affectsHosts: [] },
  { cveId: "CVE-2026-33120", vendorProject: "Microsoft", product: "Windows", name: "Microsoft Windows SMB Client Elevation of Privilege", dateAdded: "2026-11-11", shortDescription: "Windows SMB client contains an improper access control vulnerability that allows a local attacker to elevate privileges.", knownRansomwareCampaignUse: "Unknown", dueDate: "2026-12-02", affectsHosts: [] },
  { cveId: "CVE-2026-0712", vendorProject: "Ivanti", product: "Connect Secure", name: "Ivanti Connect Secure Authentication Bypass", dateAdded: "2026-11-05", shortDescription: "Ivanti Connect Secure contains an authentication bypass in the web component that allows remote access to restricted resources.", knownRansomwareCampaignUse: "Unknown", dueDate: "2026-11-26", affectsHosts: [] },
];

wildList.push(...wild);

// ---------------- helpers ----------------
const json = (data: unknown, status = 200) => Response.json(data, { status });
const err = (status: number, error: string) => json({ error }, status);

function status(): StatusResponse {
  recount();
  const totals: Record<FindingStatus, number> = { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 };
  for (const f of findings) totals[f.status]++;
  return {
    hosts,
    scan,
    totals,
    pendingActions: actions.filter((a) => a.state === "pending").length,
    inKevExposed: findings.filter((f) => f.status === "exposed" && f.inKev).length,
    recentEvents: audit.slice(0, 15),
    demo,
  };
}

function runScan(actor = "prohori") {
  if (scan.running) return false;
  scan.running = true;
  scan.lastStartedAt = iso();
  log("scan_started", actor === "prohori" ? "Scheduled scan started" : `${actor} started a scan`, { actor });
  setTimeout(() => {
    scan.running = false;
    scan.lastFinishedAt = iso();
    scan.nextRunAt = iso(settings.scanIntervalSec);
    if (demo.injected.length && findings.length === 0) seedFindings();
    scan.lastResult = { newFindings: 0, changedFindings: 0, reportsSent: 0 };
    log("scan_finished", "Scan finished: no changes");
  }, 4000);
  return true;
}

setInterval(() => {
  if (Date.parse(scan.nextRunAt ?? "") < Date.now()) runScan();
}, 1000);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Simulates the brain's rescan after a firewall change: closed port => web findings lose network exposure.
function applyFirewall(a: ActionRecord, close: boolean) {
  const inv = inventories[a.hostId];
  if (!inv) return;
  const port = Number(a.params.port);
  const protocol = (a.params.protocol as "tcp" | "udp") ?? "tcp";
  inv.firewall.closedPorts = inv.firewall.closedPorts.filter((r) => !(r.port === port && r.protocol === protocol));
  if (close) inv.firewall.closedPorts.push({ port, protocol, state: "closed", managedBy: "prohori", actionId: a.id });
  for (const f of findings) {
    if (f.hostId !== a.hostId || f.status === "not_affected") continue;
    const before = f.status;
    f.status = close ? "vulnerable_not_exposed" : "exposed";
    f.priority = close ? "high" : "critical";
    f.evidence = { ...f.evidence, firewall: close ? `${port}/${protocol} closed by Prohori rule (${a.id})` : "no Prohori firewall rules" };
    f.updatedAt = iso();
    if (before !== f.status) log("finding_changed", `${f.cveId} on ${a.hostId}: ${before} → ${f.status}`, { hostId: a.hostId, cveId: f.cveId });
  }
}

function hostName(hid: string) {
  return hosts.find((h) => h.id === hid)?.name ?? hid;
}

type ChatBody = { messages?: { id?: string; role: string; parts?: { type: string; text?: string }[] }[]; threadId?: string; actionId?: string };

function chatResponse(body: ChatBody): Response {
  const last = [...(body.messages ?? [])].reverse().find((x) => x.role === "user");
  const question = last?.parts?.filter((x) => x.type === "text").map((x) => x.text).join(" ") ?? "";
  const threadId = body.threadId ?? null;
  const reviewed = body.actionId ? actions.find((a) => a.id === body.actionId) : undefined;
  if (reviewed && threadId && !reviewed.threadId) reviewed.threadId = threadId;

  const stream = createUIMessageStream({
    originalMessages: body.messages as never,
    onFinish: ({ messages }) => {
      if (threadId) threads.set(threadId, messages);
    },
    execute: async ({ writer }) => {
      writer.write({ type: "start" });
      writer.write({ type: "start-step" });
      const callId = id("call");
      let toolName = "getHostFindings";
      let input: Record<string, unknown>;
      let output: unknown;
      let text: string;

      if (reviewed && /revise/i.test(question) && reviewed.state === "pending") {
        toolName = "reviseProposal";
        const rev = baseAction({
          id: id("a-rev"),
          hostId: reviewed.hostId,
          findingId: reviewed.findingId,
          type: "nginx_block_multipart",
          params: {},
          reason: `Revision requested in chat: block only file uploads (multipart/form-data) on ${hostName(reviewed.hostId)} instead of "${reviewed.type}". This is a PARTIAL mitigation; upgrade remains the complete fix.`,
          threadId,
          supersedes: reviewed.id,
        });
        reviewed.state = "superseded";
        reviewed.supersededBy = rev.id;
        actions.push(rev);
        log("action_revised", `Prohori revised ${reviewed.id} → ${rev.id} (block multipart uploads)`, { hostId: rev.hostId, data: { actionId: rev.id, supersedes: reviewed.id, threadId } });
        input = { actionId: reviewed.id, type: rev.type, params: rev.params };
        output = rev;
        text = `I revised the proposal: **block only multipart uploads** at nginx on ${hostName(rev.hostId)}. The site stays online, but this is **partial** — upgrade is still the only complete fix. The pinned card now shows the revision.`;
      } else if (reviewed) {
        toolName = "getAction";
        input = { actionId: reviewed.id };
        output = reviewed;
        text = `*(mock brain)* About **${reviewed.type}** on ${hostName(reviewed.hostId)}: ${reviewed.reason}\n\nYou asked: "${question}". If we don't act, bank-web-01 stays reachable by a KEV-listed RCE.`;
      } else if (/propose/i.test(question)) {
        toolName = "proposeFix";
        const a = baseAction({
          id: id("a-prop"),
          type: "firewall_port",
          params: { port: 80, protocol: "tcp", state: "closed" },
          reason: "Containment for PHP2Shell on bank-web-01 (exposed, KEV): close 80/tcp until php8.3 is upgraded.",
          threadId,
        });
        actions.push(a);
        log("action_proposed", `Prohori proposed firewall_port on ${hostName(a.hostId)}`, { hostId: a.hostId, data: { actionId: a.id, threadId } });
        input = { hostId: "web-a", type: a.type, params: a.params };
        output = a;
        text = "I proposed **closing port 80/tcp** on bank-web-01 as containment. Review it below; only an admin can approve. The complete fix is upgrading php8.3.";
      } else {
        const host = /web-02|web-b/i.test(question) ? "web-b" : /batch/i.test(question) ? "batch-c" : "web-a";
        input = { hostId: host };
        output = { host: hosts.find((h) => h.id === host), findings: findings.filter((f) => f.hostId === host).map((f) => ({ cveId: f.cveId, status: f.status, installed: f.package?.installedVersion })) };
        text = `*(mock brain)* You asked: "${question}".\n\n${RATIONALE[findings.find((f) => f.hostId === host)?.status ?? "not_affected"]}`;
      }

      writer.write({ type: "tool-input-start", toolCallId: callId, toolName, dynamic: true });
      await sleep(300);
      writer.write({ type: "tool-input-available", toolCallId: callId, toolName, input, dynamic: true });
      await sleep(600);
      writer.write({ type: "tool-output-available", toolCallId: callId, dynamic: true, output });
      writer.write({ type: "finish-step" });
      writer.write({ type: "start-step" });
      const textId = id("txt");
      writer.write({ type: "text-start", id: textId });
      for (const chunk of text.match(/.{1,24}/gs) ?? []) {
        writer.write({ type: "text-delta", id: textId, delta: chunk });
        await sleep(20);
      }
      writer.write({ type: "text-end", id: textId });
      writer.write({ type: "finish-step" });
      writer.write({ type: "finish", finishReason: "stop" });
    },
  });
  return createUIMessageStreamResponse({ stream });
}

// ---------------- routes ----------------
Bun.serve({
  port: PORT,
  hostname: "127.0.0.1",
  idleTimeout: 60,
  async fetch(req) {
    const url = new URL(req.url);
    const p = url.pathname;
    const m = req.method;
    if (TOKEN && req.headers.get("authorization") !== `Bearer ${TOKEN}`) return err(401, "bad token");
    if (!p.startsWith("/api/")) return err(404, "not found");
    const actor = req.headers.get("x-prohori-actor") || "unknown";
    const parts = p.slice(5).split("/").map(decodeURIComponent);
    const body = async () => (m === "GET" ? {} : ((await req.json().catch(() => ({}))) as Record<string, unknown>));

    try {
      if (m === "GET") {
        if (p === "/api/status") return json(status());
        if (p === "/api/hosts") return json((recount(), hosts));
        if (parts[0] === "hosts" && parts[1]) {
          const h = hosts.find((x) => x.id === parts[1]);
          if (!h) return err(404, "host not found");
          recount();
          return json({ host: h, inventory: inventories[h.id] ?? null, findings: findings.filter((f) => f.hostId === h.id) } satisfies HostDetailResponse);
        }
        if (p === "/api/findings") {
          const st = url.searchParams.get("status");
          const hid = url.searchParams.get("hostId");
          return json(findings.filter((f) => (!st || f.status === st) && (!hid || f.hostId === hid)));
        }
        if (parts[0] === "findings" && parts[1]) {
          const f = findings.find((x) => x.id === parts[1]);
          return f ? json(f) : err(404, "finding not found");
        }
        if (p === "/api/reports") return json([...reports].sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
        if (parts[0] === "reports" && parts[1]) {
          const r = reports.find((x) => x.id === parts[1]);
          return r ? json(r) : err(404, "report not found");
        }
        if (p === "/api/settings") return json(settings);
        if (p === "/api/wild") return json(wildList);
        if (p === "/api/actions") {
          const st = url.searchParams.get("state");
          const hid = url.searchParams.get("hostId");
          return json(actions.filter((a) => (!st || a.state === st) && (!hid || a.hostId === hid)));
        }
        if (parts[0] === "actions" && parts[1] && !parts[2]) {
          const a = actions.find((x) => x.id === parts[1]);
          return a ? json(a) : err(404, "action not found");
        }
        if (p === "/api/audit") {
          const hid = url.searchParams.get("hostId");
          const kind = url.searchParams.get("kind");
          return json(audit.filter((e) => (!hid || e.hostId === hid) && (!kind || e.kind === kind)).slice(0, Number(url.searchParams.get("limit") ?? 100)));
        }
        if (parts[0] === "chat" && parts[1] === "threads" && parts[2] && parts[3] === "messages") {
          return json(threads.get(parts[2]) ?? []);
        }
      }

      if (m === "PUT" && p === "/api/settings") {
        const b = await body();
        Object.assign(settings, b);
        log("settings_changed", `${actor} updated settings`, { actor, data: b });
        return json(settings);
      }

      if (m === "POST") {
        if (p === "/api/audit/login") {
          log("login", `${actor} signed in`, { actor });
          return json({ ok: true });
        }
        if (p === "/api/scan") {
          const started = runScan(actor);
          return json({ started, scan });
        }
        if (p === "/api/hosts/enroll") {
          const b = await body();
          const name = String(b.name ?? "").trim();
          if (!name) return err(400, "name required");
          const hostId = name.toLowerCase().replace(/[^a-z0-9-]+/g, "-");
          const token = crypto.randomUUID().replaceAll("-", "");
          hosts.push({ id: hostId, name, status: "offline", lastSeen: null, os: null, daemonVersion: null, tier2Enabled: false, findingCounts: { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0 }, rawMatchCount: 0 });
          log("settings_changed", `${actor} enrolled host ${name}`, { actor, hostId });
          return json({ hostId, token, installCommand: `curl -fsSL http://BRAIN:4400/install.sh | sudo PROHORI_HOST_ID=${hostId} PROHORI_TOKEN=${token} sh` } satisfies EnrollResponse);
        }
        if (parts[0] === "actions" && parts[1] && parts[2]) {
          const a = actions.find((x) => x.id === parts[1]);
          if (!a) return err(404, "action not found");
          const b = (await body()) as { note?: string; threadId?: string };
          const verb = parts[2];
          const name = hostName(a.hostId);
          if (verb === "approve" || verb === "reject") {
            if (a.state !== "pending") return err(409, `cannot ${verb} in state ${a.state}`);
            a.decidedAt = iso();
            a.decidedBy = actor;
            a.decisionNote = b.note ?? null;
            if (b.threadId) a.threadId = b.threadId;
            const data = { actionId: a.id, note: b.note, threadId: a.threadId };
            if (verb === "reject") {
              a.state = "rejected";
              log("action_rejected", `${actor} rejected ${a.type} on ${name}`, { actor, hostId: a.hostId, data });
              return json(a);
            }
            a.state = "approved";
            log("action_approved", `${actor} approved ${a.type} on ${name}`, { actor, hostId: a.hostId, data });
            setTimeout(() => (a.state = "running"), 800);
            setTimeout(() => {
              a.state = "applied";
              if (a.type === "firewall_port") {
                applyFirewall(a, a.params.state !== "open");
                a.result = { ok: true, diff: `+ prohori rule: drop ${String(a.params.protocol)} dport ${String(a.params.port)} (INPUT)`, output: "rule added; nginx on 0.0.0.0:80 is no longer reachable" };
              } else {
                a.result = {
                  ok: true,
                  diff: "- php8.3-fpm 8.3.6-0maysync1\n+ php8.3-fpm 8.3.6-0ubuntu0.24.04.13\n- php8.3-cli 8.3.6-0maysync1\n+ php8.3-cli 8.3.6-0ubuntu0.24.04.13",
                  output: "Reading package lists...\nThe following packages will be upgraded:\n  php8.3-cli php8.3-common php8.3-fpm\n3 upgraded, 0 newly installed, 0 to remove.",
                };
              }
              log("action_applied", `${a.type} applied on ${name}`, { actor: `daemon:${a.hostId}`, hostId: a.hostId, data: { actionId: a.id } });
            }, 3500);
            return json(a);
          }
          if (verb === "rollback") {
            if (a.state !== "applied") return err(409, "only applied actions can be rolled back");
            a.state = "rolled_back";
            a.rolledBackBy = actor;
            if (a.type === "firewall_port") applyFirewall(a, false);
            log("action_rolled_back", `${actor} rolled back ${a.type} on ${name}`, { actor, hostId: a.hostId, data: { actionId: a.id, note: b.note } });
            return json(a);
          }
        }
        if (p === "/api/demo/inject") {
          const b = await body();
          const ids = Array.isArray(b.cveIds) ? (b.cveIds as string[]) : [...demo.replayHeld];
          demo.replayHeld = demo.replayHeld.filter((c) => !ids.includes(c));
          demo.injected = [...new Set([...demo.injected, ...ids])];
          log("demo_inject", `${actor} released ${ids.join(", ")} for replay`, { actor });
          return json({ injected: ids });
        }
        if (p === "/api/demo/reset") {
          demo.replayHeld = [...PHP2SHELL];
          demo.injected = [];
          findings = [];
          reports = [];
          actions = [];
          for (const inv of Object.values(inventories)) inv.firewall.closedPorts = [];
          log("demo_inject", `${actor} reset the demo`, { actor });
          return json({ ok: true });
        }
        if (p === "/api/chat") {
          const b = (await body()) as ChatBody;
          console.log(`[mock-brain] chat thread=${b.threadId ?? "-"} action=${b.actionId ?? "-"} actor=${actor}`);
          return chatResponse(b);
        }
      }
      return err(404, `no route ${m} ${p}`);
    } catch (e) {
      return err(500, e instanceof Error ? e.message : String(e));
    }
  },
});

console.log(`[mock-brain] listening on http://127.0.0.1:${PORT}`);
