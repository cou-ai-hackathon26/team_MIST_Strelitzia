import type { AdvisoryJudgment, FindingStatus, JudgmentHost, JudgmentState } from "@prohori/shared";

/** What a judgeAdvisory / getJudgment tool part returns: a slim judgment with at least `id` ("jdg_…"). */
export interface JudgmentRef {
  id: string;
  url?: string;
}

export function extractJudgmentRef(output: unknown): JudgmentRef | null {
  if (!output || typeof output !== "object") return null;
  const o = output as Record<string, unknown>;
  if (typeof o.id === "string" && o.id.startsWith("jdg_")) return { id: o.id, url: typeof o.url === "string" ? o.url : undefined };
  for (const k of ["judgment", "result"]) {
    const v = o[k];
    if (v && typeof v === "object") {
      const inner = v as Record<string, unknown>;
      if (typeof inner.id === "string" && inner.id.startsWith("jdg_")) return { id: inner.id, url: typeof inner.url === "string" ? inner.url : undefined };
    }
  }
  return null;
}

export const isJudgmentRunning = (j: Pick<AdvisoryJudgment, "state"> | undefined | null) => !j || (j.state !== "done" && j.state !== "failed");

export const JUDGMENT_STATE_META: Record<JudgmentState, { label: string; tone: "blue" | "green" | "red" | "gray" | "violet" }> = {
  queued: { label: "Queued", tone: "gray" },
  fetching: { label: "Fetching Advisory", tone: "blue" },
  analysing: { label: "Analysing Advisory", tone: "blue" },
  investigating: { label: "Investigating Assets", tone: "violet" },
  done: { label: "Complete", tone: "green" },
  failed: { label: "Failed", tone: "red" },
};

export function verdictCounts(hosts: JudgmentHost[]): Record<FindingStatus, number> & { naiveVulnerable: number } {
  const c = { exposed: 0, vulnerable_not_exposed: 0, not_affected: 0, naiveVulnerable: 0 };
  for (const h of hosts) {
    c[h.status] += 1;
    if (h.naiveVerdict === "vulnerable") c.naiveVulnerable += 1;
  }
  return c;
}

/** "A version-only check flags 4 hosts; Sentinel shows 0 are actually exposed." */
export function contrastLine(j: AdvisoryJudgment): string | null {
  if (j.hosts.length === 0) return null;
  const c = verdictCounts(j.hosts);
  const n = c.naiveVulnerable;
  return `A version-only check flags ${n} ${n === 1 ? "host" : "hosts"}; Sentinel shows ${c.exposed} ${c.exposed === 1 ? "is" : "are"} actually exposed.`;
}

export function judgmentTitle(j: Pick<AdvisoryJudgment, "advisory" | "url">): string {
  return j.advisory?.title || j.url.replace(/^https?:\/\//, "");
}

/** Why "Track as findings" proposed no fixes, derived from the judgment's own data. */
export function noProposalReason(j: AdvisoryJudgment): string {
  const anyFixedBuild = j.hosts.some((h) => !!h.fixStatus.fixedVersion) || j.advisory?.fixAvailable === "yes";
  const anyExposed = j.hosts.some((h) => h.status === "exposed");
  const anyVulnerable = j.hosts.some((h) => h.status !== "not_affected");
  const reasons: string[] = [];
  if (j.hosts.length === 0) return "No fix proposed: the affected package is not installed on any asset.";
  if (!anyVulnerable) return "No fix proposed: every matched asset already runs a build that is not affected.";
  if (!anyFixedBuild) reasons.push("no fixed build exists");
  else reasons.push("no new fix was proposed for the affected assets");
  if (!anyExposed) reasons.push("no host is exposed");
  return `No fix proposed: ${reasons.join(" and ")}. The findings stay tracked and later scans keep re-checking them.`;
}

export const FIX_SOURCE_LABEL: Record<JudgmentHost["fixStatus"]["source"], string> = {
  distro_record: "Distro Record",
  advisory_only: "Advisory Only",
};

export const NAIVE_LABEL: Record<JudgmentHost["naiveVerdict"], { label: string; cls: string }> = {
  vulnerable: { label: "Vulnerable", cls: "text-red-300" },
  not_vulnerable: { label: "Not Vulnerable", cls: "text-emerald-300" },
  unknown: { label: "Unknown", cls: "text-muted" },
};
