import type { Finding, AuditEvent } from "@prohori/shared";

/** "8.3.6-0ubuntu0.24.04.13" -> "8.3.6"; "1:2.3-4" -> "2.3" */
export function upstreamVersion(v: string): string {
  const noEpoch = v.includes(":") ? v.slice(v.indexOf(":") + 1) : v;
  return noEpoch.split(/[-+~]/)[0] || noEpoch;
}

/** What a banner / naive scanner sees, e.g. "PHP 8.3.6". */
export function versionBanner(pkg: Finding["package"]): string {
  if (!pkg) return "—";
  const up = upstreamVersion(pkg.installedVersion);
  if (/^php/i.test(pkg.name)) return `PHP ${up}`;
  return `${pkg.name} ${up}`;
}

export function shortVerdictReason(f: Finding): string {
  const listening = f.evidence["listening"] ?? f.evidence["listeningPorts"] ?? f.evidence["network"];
  switch (f.status) {
    case "exposed":
      return `Vulnerable build, reachable${listening ? `: ${listening}` : " over the network"}`;
    case "vulnerable_not_exposed":
      if (f.evidence["firewall"] && /closed/i.test(f.evidence["firewall"]))
        return `Vulnerable build, contained: ${f.evidence["firewall"]}. Containment only; upgrade still required`;
      return "Vulnerable build, unreachable: no network path to the affected component. Patch in next maintenance cycle";
    case "not_affected":
      return f.package?.fixedVersion
        ? `Installed build already contains the fix (≥ ${f.package.fixedVersion}, distribution backport)`
        : "Installed build is not vulnerable";
  }
}

export const PRIORITY_RANK: Record<Finding["priority"], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const STATUS_RANK: Record<Finding["status"], number> = { exposed: 0, vulnerable_not_exposed: 1, not_affected: 2 };

export function sortFindings(a: Finding, b: Finding): number {
  return PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] || STATUS_RANK[a.status] - STATUS_RANK[b.status] || a.cveId.localeCompare(b.cveId);
}

export interface CveGroup {
  cveIds: string[];
  title: string;
  inKev: boolean;
  findings: Finding[]; // one per host
}

/**
 * Groups findings by CVE, then merges CVEs that have an identical per-host verdict signature
 * (e.g. the two PHP2Shell CVEs) so the contrast table stays compact.
 */
export function groupByCve(findings: Finding[]): CveGroup[] {
  const byCve = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byCve.get(f.cveId) ?? [];
    arr.push(f);
    byCve.set(f.cveId, arr);
  }
  const groups = new Map<string, CveGroup>();
  for (const [cve, fs] of byCve) {
    fs.sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || a.hostId.localeCompare(b.hostId));
    const sig = fs.map((f) => `${f.hostId}:${f.status}:${f.naiveVerdict}:${f.package?.installedVersion ?? ""}`).join("|");
    const g = groups.get(sig);
    if (g) {
      g.cveIds.push(cve);
      g.inKev ||= fs.some((f) => f.inKev);
    } else {
      groups.set(sig, { cveIds: [cve], title: fs[0]!.title, inKev: fs.some((f) => f.inKev), findings: fs });
    }
  }
  // Most severe group first: compare each group's most severe finding (priority, then status).
  const head = (g: CveGroup) => [...g.findings].sort(sortFindings)[0]!;
  return [...groups.values()].sort((a, b) => sortFindings(head(a), head(b)) || Number(b.inKev) - Number(a.inKev));
}

export const EVENT_TONE: Partial<Record<AuditEvent["kind"], string>> = {
  finding_new: "text-red-400",
  finding_changed: "text-amber-400",
  report_sent: "text-blue-400",
  action_proposed: "text-violet-400",
  action_approved: "text-emerald-400",
  action_applied: "text-emerald-400",
  action_failed: "text-red-400",
  action_rejected: "text-slate-400",
  action_rolled_back: "text-amber-400",
  host_online: "text-emerald-400",
  host_offline: "text-slate-400",
  demo_inject: "text-violet-400",
  error: "text-red-400",
  cve_discovered: "text-orange-400",
  vulnerable_detected: "text-red-400",
  report_generated: "text-blue-300",
  action_revised: "text-violet-300",
  login: "text-slate-300",
  scan_started: "text-sky-400",
  scan_finished: "text-sky-400",
  settings_changed: "text-slate-300",
  judgment_requested: "text-sky-300",
  judgment_done: "text-violet-400",
  judgment_tracked: "text-emerald-400",
};

/** "prohori" -> "Prohori", "daemon:web-a" stays, usernames stay. */
export function actorLabel(actor: string | undefined | null): string {
  if (!actor) return "Unknown";
  if (actor === "prohori" || actor === "system" || actor === "agent") return "Sentinel";
  return actor;
}

export function actorKind(actor: string | undefined | null): "system" | "daemon" | "human" {
  if (!actor || actor === "prohori" || actor === "system" || actor === "agent") return "system";
  if (actor.startsWith("daemon:")) return "daemon";
  return "human";
}
