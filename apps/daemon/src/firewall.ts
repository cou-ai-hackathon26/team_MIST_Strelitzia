// Host firewall (iptables INPUT). Prohori only ever reads/adds/removes rules whose comment starts with "prohori".
import type { FirewallRule } from "@prohori/shared";
import { fmt, priv, run } from "./exec";

const TAG = "prohori";

export interface ManagedRule {
  spec: string[]; // rule spec without the "-A INPUT" prefix (usable with -I INPUT 1 / -D INPUT)
  port: number;
  protocol: "tcp" | "udp";
  comment: string;
  actionId: string | null;
}

/** Split an `iptables -S` line, honouring double quotes. */
function tokenize(line: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) out.push(m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]!);
  return out;
}

export async function listRules(): Promise<{ available: boolean; rules: ManagedRule[]; error?: string }> {
  const r = await run(priv(["iptables", "-S", "INPUT"]), { timeoutMs: 15_000 });
  if (r.code !== 0) return { available: false, rules: [], error: (r.stderr || r.stdout).trim() };
  const rules: ManagedRule[] = [];
  for (const line of r.stdout.split("\n")) {
    const t = tokenize(line.trim());
    if (t[0] !== "-A" || t[1] !== "INPUT") continue;
    const ci = t.indexOf("--comment");
    const comment = ci >= 0 ? (t[ci + 1] ?? "") : "";
    if (comment !== TAG && !comment.startsWith(`${TAG}:`)) continue;
    const pi = t.indexOf("-p");
    const di = t.indexOf("--dport");
    const protocol = t[pi + 1];
    if (pi < 0 || di < 0 || (protocol !== "tcp" && protocol !== "udp")) continue;
    rules.push({
      spec: t.slice(2),
      port: Number(t[di + 1]),
      protocol,
      comment,
      actionId: comment.startsWith(`${TAG}:`) ? comment.slice(TAG.length + 1) || null : null,
    });
  }
  return { available: true, rules };
}

export function toFirewallRules(rules: ManagedRule[]): FirewallRule[] {
  const seen = new Set<string>();
  return rules
    .filter((r) => {
      const k = `${r.protocol}/${r.port}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    })
    .map((r) => ({ port: r.port, protocol: r.protocol, state: "closed" as const, managedBy: "prohori" as const, actionId: r.actionId }))
    .sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
}

export async function getFirewall(): Promise<{ available: boolean; closedPorts: FirewallRule[] }> {
  const { available, rules } = await listRules();
  return { available, closedPorts: toFirewallRules(rules) };
}

export function closeSpec(port: number, protocol: "tcp" | "udp", actionId: string): string[] {
  const target = protocol === "tcp" ? ["-j", "REJECT", "--reject-with", "tcp-reset"] : ["-j", "DROP"];
  return ["-p", protocol, "-m", protocol, "--dport", String(port), "-m", "comment", "--comment", `${TAG}:${actionId}`, ...target];
}

export async function insertRule(spec: string[]): Promise<{ ok: boolean; out: string }> {
  const argv = ["iptables", "-I", "INPUT", "1", ...spec];
  const r = await run(priv(argv), { timeoutMs: 15_000 });
  return { ok: r.code === 0, out: fmt(argv, r) };
}

export async function deleteRule(spec: string[]): Promise<{ ok: boolean; out: string }> {
  if (!spec.includes("--comment")) return { ok: false, out: "refusing to delete a rule without the prohori comment\n" };
  const argv = ["iptables", "-D", "INPUT", ...spec];
  const r = await run(priv(argv), { timeoutMs: 15_000 });
  return { ok: r.code === 0, out: fmt(argv, r) };
}

export function describe(rules: ManagedRule[]): string {
  if (!rules.length) return "  (none)";
  return toFirewallRules(rules).map((r) => `  ${r.port}/${r.protocol} closed${r.actionId ? ` (${r.actionId})` : ""}`).join("\n");
}
