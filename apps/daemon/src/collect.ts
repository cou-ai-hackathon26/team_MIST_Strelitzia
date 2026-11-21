// Named queries. The SQL lives only here; the network can reference QUERY_NAMES, nothing else.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { PHP_DIRECTIVES, type InstalledPackage, type InventorySnapshot, type ListeningPort, type OsInfo, type QueryName } from "@prohori/shared";
import { run } from "./exec";
import { getFirewall } from "./firewall";
import { readConfigFile } from "./configfile";

let OSQUERYI = "osqueryi";
export function setOsqueryi(path: string) {
  OSQUERYI = path;
}

type Row = Record<string, string>;

export async function osquery(sql: string): Promise<Row[]> {
  const r = await run([OSQUERYI, "--json", sql], { timeoutMs: 30_000 });
  if (r.code !== 0) throw new Error(`osqueryi failed (exit ${r.code}): ${(r.stderr || r.stdout).trim().slice(0, 500)}`);
  return JSON.parse(r.stdout || "[]") as Row[];
}

const SQL = {
  packages: "SELECT name, version, source, arch FROM deb_packages WHERE status LIKE '%installed%';",
  os_version: "SELECT name, version, major, minor, codename, platform FROM os_version;",
  listening_ports:
    "SELECT l.port, l.protocol, l.address, l.pid, p.name AS process FROM listening_ports l LEFT JOIN processes p ON p.pid = l.pid WHERE l.port > 0;",
  processes: "SELECT name, path, pid FROM processes;",
} as const;

export async function getPackages(): Promise<InstalledPackage[]> {
  let rows: Row[];
  try {
    rows = await osquery(SQL.packages);
  } catch {
    // older osquery builds lack the status column filter semantics; fall back to all rows
    rows = await osquery("SELECT name, version, source, arch FROM deb_packages;");
  }
  return rows
    .map((r) => ({
      name: r.name ?? "",
      version: r.version ?? "",
      // empty source => source package == binary package; strip "php8.3 (8.3.6-...)" version suffix
      source: (r.source ?? "").replace(/\s*\(.*\)\s*$/, "").trim() || (r.name ?? ""),
      arch: r.arch ?? "",
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export async function getOs(): Promise<OsInfo> {
  const [r] = await osquery(SQL.os_version);
  if (!r) throw new Error("os_version returned no rows");
  const minor = r.minor ?? "";
  return {
    name: r.name ?? "",
    version: r.version ?? "",
    // Ubuntu style "24.04" (osquery reports minor "4")
    versionId: minor !== "" ? `${r.major}.${minor.padStart(2, "0")}` : (r.major ?? ""),
    codename: r.codename ?? "",
    platform: r.platform ?? "",
  };
}

export async function getListeningPorts(): Promise<ListeningPort[]> {
  const rows = await osquery(SQL.listening_ports);
  const seen = new Set<string>();
  const out: ListeningPort[] = [];
  for (const r of rows) {
    const proto = r.protocol === "6" ? "tcp" : r.protocol === "17" ? "udp" : null;
    if (!proto) continue;
    // Docker's embedded DNS resolver (127.0.0.11) lives in the container netns but belongs to dockerd: not a host service.
    if (r.address === "127.0.0.11" && !r.process) continue;
    const p: ListeningPort = {
      port: Number(r.port),
      protocol: proto,
      address: r.address ?? "",
      process: r.process ?? "",
      pid: Number(r.pid ?? -1),
    };
    const key = `${p.protocol}|${p.address}|${p.port}|${p.pid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol) || a.address.localeCompare(b.address) || a.pid - b.pid);
}

export async function getProcesses(): Promise<{ name: string; path: string; pid: number }[]> {
  const rows = await osquery(SQL.processes);
  return rows.map((r) => ({ name: r.name ?? "", path: r.path ?? "", pid: Number(r.pid) })).sort((a, b) => a.pid - b.pid);
}

// ---------- config files (read directly) ----------

const PHP_SAPIS = ["fpm", "cli", "apache2"] as const;

export function phpIniFiles(): string[] {
  const base = "/etc/php";
  if (!existsSync(base)) return [];
  const files: string[] = [];
  for (const ver of readdirSync(base).sort()) {
    for (const sapi of PHP_SAPIS) {
      const f = join(base, ver, sapi, "php.ini");
      if (existsSync(f)) files.push(f);
    }
  }
  return files;
}

/** Effective value = last uncommented `directive = value` line. */
export function iniValue(text: string, directive: string): string | null {
  let val: string | null = null;
  const re = new RegExp(`^\\s*${directive.replace(/\./g, "\\.")}\\s*=\\s*(.*?)\\s*$`);
  for (const line of text.split("\n")) {
    const m = re.exec(line);
    if (m) val = m[1]!.replace(/^"(.*)"$/, "$1");
  }
  return val;
}

export function getPhpConfig(): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [];
  for (const f of phpIniFiles()) {
    const text = readFileSync(f, "utf8");
    for (const d of PHP_DIRECTIVES) {
      const v = iniValue(text, d);
      if (v !== null) out.push({ key: `${f}:${d}`, value: v });
    }
  }
  return out;
}

export const MULTIPART_SNIPPET = "/etc/nginx/prohori/block-multipart.conf";

function nginxFiles(): string[] {
  const files: string[] = [];
  if (existsSync("/etc/nginx/nginx.conf")) files.push("/etc/nginx/nginx.conf");
  for (const dir of ["/etc/nginx/conf.d", "/etc/nginx/sites-enabled", "/etc/nginx/prohori"]) {
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).sort()) {
      const p = join(dir, f);
      try {
        if (statSync(p).isFile()) files.push(p);
      } catch {
        /* dangling symlink */
      }
    }
  }
  return files;
}

export function getNginxConfig(): { key: string; value: string }[] {
  if (!existsSync("/etc/nginx")) return [];
  const out: { key: string; value: string }[] = [];
  for (const f of nginxFiles()) {
    const text = readFileSync(f, "utf8");
    for (const line of text.split("\n")) {
      const m = /^\s*client_max_body_size\s+([^;\s]+)\s*;/.exec(line);
      if (m) out.push({ key: `${f}:client_max_body_size`, value: m[1]! });
    }
  }
  out.push({ key: "nginx:multipart_blocked", value: existsSync(MULTIPART_SNIPPET) ? "true" : "false" });
  return out;
}

// ---------- services ----------

/** `{name, state}[]`: systemd units when systemd is PID 1, else SysV `service --status-all` (containers). */
export async function getServices(): Promise<{ name: string; state: string }[]> {
  if (existsSync("/run/systemd/system")) {
    const r = await run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"], { timeoutMs: 20_000 });
    if (r.code !== 0) throw new Error(`systemctl failed (exit ${r.code}): ${(r.stderr || r.stdout).trim().slice(0, 300)}`);
    const out: { name: string; state: string }[] = [];
    for (const line of r.stdout.split("\n")) {
      // UNIT LOAD ACTIVE SUB DESCRIPTION
      const [unit, load, , sub] = line.trim().split(/\s+/);
      if (!unit?.endsWith(".service") || load === "not-found") continue;
      out.push({ name: unit.slice(0, -".service".length), state: sub ?? "unknown" });
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }
  const r = await run(["service", "--status-all"], { timeoutMs: 30_000 });
  if (r.code !== 0 && !r.stdout.trim()) throw new Error(`service --status-all failed (exit ${r.code}): ${r.stderr.trim().slice(0, 300)}`);
  const states: Record<string, string> = { "+": "running", "-": "stopped", "?": "unknown" };
  const out: { name: string; state: string }[] = [];
  for (const line of (r.stdout + "\n" + r.stderr).split("\n")) {
    const m = /^\s*\[\s*([+?-])\s*\]\s+(\S+)/.exec(line);
    if (m) out.push({ name: m[2]!, state: states[m[1]!]! });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// ---------- dispatch ----------

export async function runNamedQuery(name: QueryName, params: Record<string, string> = {}): Promise<Record<string, unknown>[]> {
  switch (name) {
    case "packages":
      return getPackages() as unknown as Promise<Record<string, unknown>[]>;
    case "os_version":
      return [(await getOs()) as unknown as Record<string, unknown>];
    case "listening_ports":
      return getListeningPorts() as unknown as Promise<Record<string, unknown>[]>;
    case "processes":
      return getProcesses();
    case "php_config":
      return getPhpConfig();
    case "firewall_rules": {
      const fw = await getFirewall();
      if (!fw.available) throw new Error("firewall tooling (iptables) is not available on this host");
      return fw.closedPorts as unknown as Record<string, unknown>[];
    }
    case "nginx_config":
      return getNginxConfig();
    case "config_file":
      return readConfigFile(params.path);
    case "services":
      return getServices();
  }
}

export function getConfigMap(): Record<string, string> {
  const config: Record<string, string> = {};
  for (const { key, value } of [...getPhpConfig(), ...getNginxConfig()]) config[key] = value;
  return config;
}

export async function collectSnapshot(): Promise<InventorySnapshot> {
  const [os, packages, listeningPorts, processes, firewall] = await Promise.all([getOs(), getPackages(), getListeningPorts(), getProcesses(), getFirewall()]);
  return {
    collectedAt: new Date().toISOString(),
    hostname: hostname(),
    os,
    packages,
    listeningPorts,
    processes,
    firewall,
    config: getConfigMap(),
  };
}

/** Fingerprint of the parts that matter for change detection (packages + listening ports + configs). */
export async function changeFingerprint(): Promise<string> {
  const [packages, ports, firewall] = await Promise.all([getPackages(), getListeningPorts(), getFirewall()]);
  // pids churn on restarts; compare listeners without pid
  const portKey = ports.map((p) => `${p.protocol}|${p.address}|${p.port}|${p.process}`);
  return JSON.stringify([packages, [...new Set(portKey)].sort(), firewall, getConfigMap()]);
}
