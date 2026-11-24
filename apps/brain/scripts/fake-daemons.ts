// Fake prohori-daemons for brain development: web-a, web-b, batch-c, ssh-d with realistic inventories.
// Usage: bun scripts/fake-daemons.ts [ws://127.0.0.1:4000/agent] [--only ssh-d,batch-c]
import { ActionParams, BrainToDaemon, PROTOCOL_VERSION, type ActionType, type InventorySnapshot } from "@prohori/shared";

const ONLY = (() => { const i = process.argv.indexOf("--only"); return i > 0 ? new Set(process.argv[i + 1]!.split(",")) : null; })();
const URL_ = (process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : undefined) ?? process.env.BRAIN_WS ?? `ws://127.0.0.1:${process.env.BRAIN_PORT ?? 4000}/agent`;
const VULN = "8.3.6-0maysync1";
const PATCHED = "8.3.6-0ubuntu0.24.04.13";

const os = { name: "Ubuntu", version: "24.04.3 LTS (Noble Numbat)", versionId: "24.04", codename: "noble", platform: "ubuntu" };
const base = [
  { name: "nginx", version: "1.24.0-2ubuntu7.5", source: "nginx", arch: "amd64" },
  { name: "nginx-common", version: "1.24.0-2ubuntu7.5", source: "nginx", arch: "all" },
  { name: "openssl", version: "3.0.13-0ubuntu3.6", source: "openssl", arch: "amd64" },
  { name: "libc6", version: "2.39-0ubuntu8.6", source: "glibc", arch: "amd64" },
  { name: "osquery", version: "5.19.0-1.linux", source: "osquery", arch: "amd64" },
];
const SSH_VULN = "1:9.6p1-3ubuntu13";
const SSH_PATCHED = "1:9.6p1-3ubuntu13.20";
const ssh = (v: string, names: string[]) => names.map((n) => ({ name: n, version: v, source: "openssh", arch: "amd64" }));
const sshdListener = { port: 22, protocol: "tcp" as const, address: "0.0.0.0", process: "sshd", pid: 22 };
const sshdProc = { name: "sshd", path: "/usr/sbin/sshd", pid: 22 };
const sshdConfig: Record<string, string> = { "/etc/ssh/sshd_config:PermitRootLogin": "prohibit-password", "/etc/ssh/sshd_config:PasswordAuthentication": "yes", "/etc/ssh/sshd_config:UsePAM": "yes" };
const php = (v: string, names: string[]) => names.map((n) => ({ name: n, version: v, source: "php8.3", arch: "amd64" }));
const phpConfig = (sapis: string[]) =>
  Object.fromEntries(sapis.flatMap((s) => [
    [`/etc/php/8.3/${s}/php.ini:memory_limit`, s === "cli" ? "-1" : "128M"],
    [`/etc/php/8.3/${s}/php.ini:post_max_size`, "8M"],
    [`/etc/php/8.3/${s}/php.ini:upload_max_filesize`, "2M"],
    [`/etc/php/8.3/${s}/php.ini:max_input_nesting_level`, "64"],
    [`/etc/php/8.3/${s}/php.ini:max_input_vars`, "1000"],
    [`/etc/php/8.3/${s}/php.ini:file_uploads`, "On"],
  ]));

function webHost(hostname: string, phpVersion: string): InventorySnapshot {
  return {
    collectedAt: new Date().toISOString(),
    hostname,
    os,
    packages: [...base, ...php(phpVersion, ["php8.3-fpm", "php8.3-cli", "php8.3-common", "php8.3-opcache", "php8.3-readline"])],
    listeningPorts: [
      { port: 80, protocol: "tcp", address: "0.0.0.0", process: "nginx", pid: 101 },
      { port: 9000, protocol: "tcp", address: "127.0.0.1", process: "php-fpm8.3", pid: 120 },
    ],
    processes: [
      { name: "nginx", path: "/usr/sbin/nginx", pid: 101 },
      { name: "php-fpm8.3", path: "/usr/sbin/php-fpm8.3", pid: 120 },
      { name: "osqueryd", path: "/opt/osquery/bin/osqueryd", pid: 50 },
      { name: "prohori-daemon", path: "/usr/local/bin/prohori-daemon", pid: 60 },
    ],
    firewall: { available: true, closedPorts: [] },
    config: { ...phpConfig(["fpm", "cli"]), "/etc/nginx/nginx.conf:client_max_body_size": "8m", "/etc/nginx/sites-enabled/bank:multipart_block": "off" },
  };
}

const hosts: { id: string; token: string; inv: InventorySnapshot }[] = [
  { id: "web-a", token: "dev-token-a", inv: webHost("bank-web-01", VULN) },
  { id: "web-b", token: "dev-token-b", inv: (() => {
    const inv = webHost("bank-web-02", PATCHED);
    inv.packages.push(...ssh(SSH_PATCHED, ["openssh-server", "openssh-client", "openssh-sftp-server"]));
    inv.listeningPorts.push(sshdListener);
    inv.processes.push(sshdProc);
    Object.assign(inv.config, sshdConfig);
    return inv;
  })() },
  {
    id: "ssh-d", token: "dev-token-d", inv: {
      collectedAt: new Date().toISOString(), hostname: "bank-ssh-01", os,
      packages: [...base.filter((p) => p.source !== "nginx"), ...ssh(SSH_VULN, ["openssh-server", "openssh-client", "openssh-sftp-server"])],
      listeningPorts: [sshdListener],
      processes: [sshdProc, { name: "osqueryd", path: "/opt/osquery/bin/osqueryd", pid: 50 }],
      firewall: { available: true, closedPorts: [] },
      config: { ...sshdConfig },
    },
  },
  {
    id: "batch-c", token: "dev-token-c", inv: {
      collectedAt: new Date().toISOString(), hostname: "bank-batch-01", os,
      packages: [...base.filter((p) => p.source !== "nginx"), ...php(VULN, ["php8.3-cli", "php8.3-common", "php8.3-readline"]), ...ssh(SSH_VULN, ["openssh-client"])],
      listeningPorts: [],
      processes: [{ name: "cron", path: "/usr/sbin/cron", pid: 30 }, { name: "osqueryd", path: "/opt/osquery/bin/osqueryd", pid: 50 }],
      firewall: { available: true, closedPorts: [] },
      config: phpConfig(["cli"]),
    },
  },
];

function rowsFor(inv: InventorySnapshot, name: string, params: Record<string, string> = {}): Record<string, unknown>[] {
  switch (name) {
    case "config_file": {
      const path = params.path ?? "";
      return Object.entries(inv.config).filter(([k]) => k.startsWith(path + ":")).map(([k, value]) => ({ key: k.slice(path.length + 1), value, file: path }));
    }
    case "services": return [...new Set(inv.processes.map((p) => p.name))].filter((n) => !/osquery|prohori/.test(n)).map((name) => ({ name: name === "sshd" ? "ssh" : name, state: "running" }));
    case "packages": return inv.packages as any;
    case "os_version": return [inv.os as any];
    case "listening_ports": return inv.listeningPorts as any;
    case "processes": return inv.processes as any;
    case "firewall_rules": return inv.firewall.closedPorts as any;
    case "php_config": return Object.entries(inv.config).filter(([k]) => k.includes("php")).map(([key, value]) => ({ key, value }));
    case "nginx_config": return Object.entries(inv.config).filter(([k]) => k.includes("nginx")).map(([key, value]) => ({ key, value }));
    default: return [];
  }
}

function connect(h: (typeof hosts)[number]) {
  const ws = new WebSocket(URL_);
  const undo = new Map<string, () => string>();
  const send = (m: object) => ws.send(JSON.stringify({ id: crypto.randomUUID(), ...m }));
  const sendInv = (reason: "connect" | "periodic" | "changed") => {
    h.inv.collectedAt = new Date().toISOString();
    send({ type: "inventory", reason, snapshot: h.inv });
  };
  let hb: Timer | null = null;
  let inv: Timer | null = null;
  ws.onopen = () => send({ type: "hello", hostId: h.id, token: h.token, daemonVersion: "0.1.0-fake", protocolVersion: PROTOCOL_VERSION });
  ws.onmessage = (ev) => {
    const parsed = BrainToDaemon.safeParse(JSON.parse(String(ev.data)));
    if (!parsed.success) return console.error(`[${h.id}] bad msg`, ev.data);
    const m = parsed.data;
    switch (m.type) {
      case "welcome":
        console.log(`[${h.id}] welcome`);
        sendInv("connect");
        hb = setInterval(() => send({ type: "heartbeat", at: new Date().toISOString() }), m.heartbeatSec * 1000);
        inv = setInterval(() => sendInv("periodic"), m.inventorySec * 1000);
        break;
      case "reject":
        console.error(`[${h.id}] rejected: ${m.reason}`);
        break;
      case "query":
        send({ type: "query_result", requestId: m.requestId, ok: true, rows: rowsFor(h.inv, m.name, m.params ?? {}) });
        break;
      case "refresh":
        sendInv("periodic");
        break;
      case "action": {
        const type = m.actionType as ActionType;
        const p = ActionParams[type].safeParse(m.params);
        if (!p.success) {
          send({ type: "action_result", actionId: m.actionId, kind: "apply", ok: false, diff: "", output: "params rejected by daemon" });
          break;
        }
        let diff = "";
        if (type === "upgrade_packages") {
          const names = (p.data as { packages: string[] }).packages;
          const prev = new Map(h.inv.packages.filter((x) => names.includes(x.name)).map((x) => [x.name, x.version]));
          const target = (src: string) => (src === "openssh" ? SSH_PATCHED : PATCHED);
          for (const x of h.inv.packages) if (names.includes(x.name)) x.version = target(x.source);
          diff = [...prev].map(([n, v]) => `${n}: ${v} -> patched`).join("\n");
          undo.set(m.actionId, () => {
            for (const x of h.inv.packages) if (prev.has(x.name)) x.version = prev.get(x.name)!;
            return [...prev].map(([n, v]) => `${n}: patched -> ${v}`).join("\n");
          });
        } else if (type === "firewall_port") {
          const { port, protocol, state } = p.data as { port: number; protocol: "tcp" | "udp"; state: "closed" | "open" };
          const before = [...h.inv.firewall.closedPorts];
          h.inv.firewall.closedPorts = h.inv.firewall.closedPorts.filter((r) => !(r.port === port && r.protocol === protocol));
          if (state === "closed") h.inv.firewall.closedPorts.push({ port, protocol, state: "closed", managedBy: "prohori", actionId: m.actionId });
          diff = `iptables INPUT: ${port}/${protocol} ${state === "closed" ? "open -> closed (DROP, comment prohori)" : "closed -> open"}`;
          undo.set(m.actionId, () => {
            h.inv.firewall.closedPorts = before;
            return `iptables INPUT: ${port}/${protocol} restored (${state === "closed" ? "open" : "closed"})`;
          });
        } else {
          diff = `${type} ${JSON.stringify(p.data)} applied (fake)`;
          undo.set(m.actionId, () => `${type} reverted (fake)`);
        }
        console.log(`[${h.id}] applied ${type}: ${diff}`);
        setTimeout(() => {
          send({ type: "action_result", actionId: m.actionId, kind: "apply", ok: true, diff, output: `fake daemon: ${type} ok` });
          sendInv("changed");
        }, 1500);
        break;
      }
      case "rollback": {
        const u = undo.get(m.actionId);
        const diff = u ? u() : "";
        undo.delete(m.actionId);
        console.log(`[${h.id}] rollback ${m.actionId}: ${diff}`);
        setTimeout(() => {
          send({ type: "action_result", actionId: m.actionId, kind: "rollback", ok: !!u, diff, output: u ? "fake daemon: rolled back" : "nothing to roll back" });
          sendInv("changed");
        }, 1000);
        break;
      }
    }
  };
  ws.onclose = (e) => {
    if (hb) clearInterval(hb);
    if (inv) clearInterval(inv);
    console.log(`[${h.id}] closed (${e.code} ${e.reason}); reconnecting in 3s`);
    setTimeout(() => connect(h), 3000);
  };
  ws.onerror = () => {};
}

for (const h of hosts) if (!ONLY || ONLY.has(h.id)) connect(h);
console.log(`fake daemons → ${URL_}`);
