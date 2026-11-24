// Read-only host facts for Sentinel's investigator and planner: a compact inventory slice plus live named queries
// (with a fallback to the stored inventory when a daemon does not support a query yet).
import { CONFIG_PATHS, QUERY_NAMES, type InventorySnapshot, type QueryName } from "@prohori/shared";
import { getHostRow, getInventory } from "../db";
import { blockReason } from "../health";
import { isOnline, queryHost } from "../gateway";
import { closedPortsOf, isLoopback, sourcesOf } from "./engine";

export interface HostFacts {
  hostId: string;
  hostName: string;
  collectedAt: string | null;
  os: string | null;
  sourcePackage: string | null;
  installedBinaries: { name: string; version: string }[];
  listeners: { address: string; port: number; protocol: string; process: string; pid: number; firewalled: boolean }[];
  loopbackListeners: string[];
  runningProcesses: { name: string; path: string; count: number }[];
  firewall: { available: boolean; closedPorts: string[] };
  config: Record<string, string>;
  note?: string;
}

export function hostFacts(hostId: string, sourcePackage: string | null): HostFacts | { error: string } {
  const row = getHostRow(hostId);
  const inv = getInventory(hostId);
  if (!row || !inv) return { error: `no inventory for host ${hostId}` };
  const why = blockReason(hostId);
  if (why) return { error: `host ${row.name} cannot be assessed (${why}); its stored inventory is not trustworthy` };
  return factsFromInventory(hostId, row.name, inv, sourcePackage);
}

export function factsFromInventory(hostId: string, hostName: string, inv: InventorySnapshot, sourcePackage: string | null): HostFacts {
  const closed = closedPortsOf(inv);
  const src = sourcePackage ? sourcesOf(inv).get(sourcePackage) : null;
  const procs = new Map<string, { name: string; path: string; count: number }>();
  for (const p of inv.processes ?? []) {
    const k = `${p.name}|${p.path}`;
    const e = procs.get(k);
    if (e) e.count++;
    else procs.set(k, { name: p.name, path: p.path, count: 1 });
  }
  const seen = new Set<string>();
  const listeners: HostFacts["listeners"] = [];
  for (const p of inv.listeningPorts ?? []) {
    if (isLoopback(p.address)) continue;
    const protocol = p.protocol ?? "tcp";
    const k = `${p.address}:${p.port}/${protocol}`;
    if (seen.has(k)) continue;
    seen.add(k);
    listeners.push({ address: p.address, port: p.port, protocol, process: p.process, pid: p.pid, firewalled: closed.has(`${p.port}/${protocol}`) });
  }
  return {
    hostId,
    hostName,
    collectedAt: inv.collectedAt ?? null,
    os: inv.os ? `${inv.os.name} ${inv.os.version}` : null,
    sourcePackage,
    installedBinaries: (src?.binaries ?? []).map((b) => ({ name: b.name, version: b.version })),
    listeners,
    loopbackListeners: [...new Set((inv.listeningPorts ?? []).filter((p) => isLoopback(p.address)).map((p) => `${p.address}:${p.port}/${p.protocol ?? "tcp"} ${p.process}`))],
    runningProcesses: [...procs.values()].sort((a, b) => a.name.localeCompare(b.name)),
    firewall: { available: inv.firewall?.available !== false, closedPorts: [...closed].sort() },
    config: inv.config ?? {},
    ...(listeners.length ? {} : { note: "nothing listens on a non-loopback address" }),
  };
}

const globToRe = (g: string) => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*") + "$");
/** Same rule the daemon enforces for package_files: Debian binary package name, optional `:arch`. */
export const DEB_PACKAGE_RE = /^[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9-]+)?$/;

export const configPathAllowed = (path: string) => CONFIG_PATHS.some((g) => globToRe(g).test(path));

/** Live named query on a host; falls back to the stored inventory if the daemon is offline or lacks the query. */
export async function hostQuery(hostId: string, name: string, params: Record<string, string> = {}): Promise<{
  source: "live" | "stored_inventory"; rows: Record<string, unknown>[]; note?: string; error?: string;
}> {
  if (!(QUERY_NAMES as readonly string[]).includes(name)) return { source: "live", rows: [], error: `unknown query "${name}"; allowed: ${QUERY_NAMES.join(", ")}` };
  if (name === "config_file") {
    const path = params.path ?? "";
    if (!configPathAllowed(path)) return { source: "live", rows: [], error: `config_file path must match one of: ${CONFIG_PATHS.join(", ")}` };
  }
  if (name === "package_files" && !DEB_PACKAGE_RE.test(params.package ?? "")) {
    return { source: "live", rows: [], error: `package_files requires params {"package": "<binary package name>"} (lowercase Debian name, optional :arch), got ${JSON.stringify(params.package ?? "")}` };
  }
  let liveError = "";
  if (isOnline(hostId)) {
    try {
      const qp: Record<string, string> | undefined = name === "config_file" ? { path: params.path! } : name === "package_files" ? { package: params.package! } : undefined;
      const rows = await queryHost(hostId, name as QueryName, qp);
      return { source: "live", rows };
    } catch (e) {
      liveError = (e as Error).message;
    }
  } else liveError = "host offline";
  if (name === "package_files") {
    // a definitive daemon answer ("not installed") is a fact, not a transport failure
    if (/is not installed/.test(liveError)) return { source: "live", rows: [], error: liveError };
    // the stored inventory has no per-package file lists: never answer with unrelated data
    return { source: "stored_inventory", rows: [], error: `live query failed (${liveError}); file lists are only available live from the daemon (host offline or daemon too old)` };
  }
  const why = blockReason(hostId);
  if (why) return { source: "stored_inventory", rows: [], error: `live query failed (${liveError}) and the stored inventory cannot be trusted: ${why}` };
  const inv = getInventory(hostId);
  if (!inv) return { source: "stored_inventory", rows: [], error: `live query failed (${liveError}) and no stored inventory` };
  const note = `live query unavailable (${liveError}); answered from the stored inventory collected ${inv.collectedAt}`;
  return { source: "stored_inventory", rows: fromInventory(inv, name, params), note };
}

function fromInventory(inv: InventorySnapshot, name: string, params: Record<string, string>): Record<string, unknown>[] {
  switch (name) {
    case "packages": return inv.packages as any;
    case "os_version": return [inv.os as any];
    case "listening_ports": return inv.listeningPorts as any;
    case "processes": return inv.processes as any;
    case "firewall_rules": return inv.firewall.closedPorts as any;
    case "config_file": {
      const re = globToRe(params.path ?? "");
      return Object.entries(inv.config ?? {})
        .filter(([k]) => re.test(k.slice(0, k.lastIndexOf(":"))))
        .map(([k, value]) => ({ file: k.slice(0, k.lastIndexOf(":")), key: k.slice(k.lastIndexOf(":") + 1), value }));
    }
    case "package_files": return []; // no file lists in the stored inventory (hostQuery returns an error before this)
    case "services": {
      // no service list in the stored inventory: report running processes as a proxy
      return [...new Set((inv.processes ?? []).map((p) => p.name))].map((n) => ({ name: n, state: "running (process)" }));
    }
    default: {
      const prefix = name.replace(/_config$/, "");
      return Object.entries(inv.config ?? {}).filter(([k]) => k.toLowerCase().includes(prefix)).map(([key, value]) => ({ key, value }));
    }
  }
}
