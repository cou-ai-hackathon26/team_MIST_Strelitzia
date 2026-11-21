import type { ActionRecord, ActionState } from "@prohori/shared";

export const STATE_TONE: Record<ActionState, "amber" | "blue" | "green" | "red" | "gray" | "violet"> = {
  pending: "amber",
  approved: "blue",
  running: "blue",
  applied: "green",
  failed: "red",
  rejected: "gray",
  rolled_back: "violet",
  superseded: "gray",
};

export type ActionKind = "containment" | "fix" | "partial" | "other";

export function actionKind(a: Pick<ActionRecord, "type">): ActionKind {
  switch (a.type) {
    case "firewall_port":
      return "containment";
    case "upgrade_packages":
      return "fix";
    case "nginx_block_multipart":
    case "set_php_directive":
      return "partial";
    default:
      return "other";
  }
}

/** Human sentence for an action, e.g. "Close port 80/tcp on bank-web-01". */
export function actionTitle(a: Pick<ActionRecord, "type" | "params">, hostName: string): string {
  const p = a.params as Record<string, unknown>;
  switch (a.type) {
    case "firewall_port":
      return `${p.state === "open" ? "Re-open" : "Close"} port ${String(p.port)}/${String(p.protocol ?? "tcp")} on ${hostName}`;
    case "upgrade_packages":
      return `Upgrade ${Array.isArray(p.packages) ? p.packages.join(", ") : "packages"} on ${hostName}`;
    case "set_php_directive":
      return `Set ${String(p.directive)} = ${String(p.value)} (php ${String(p.sapi)}) on ${hostName}`;
    case "restart_service":
      return `Restart ${String(p.service)} on ${hostName}`;
    case "nginx_block_multipart":
      return `Block multipart/form-data uploads in nginx on ${hostName}`;
    default:
      return `${String(a.type)} on ${hostName}`;
  }
}

/** Plain-language consequence shown before approving. */
export function actionConsequence(a: Pick<ActionRecord, "type" | "params">): string {
  const p = a.params as Record<string, unknown>;
  switch (a.type) {
    case "firewall_port":
      return p.state === "open"
        ? `Port ${String(p.port)}/${String(p.protocol)} becomes reachable again.`
        : `Containment — the service on port ${String(p.port)}/${String(p.protocol)} goes offline for everyone. Upgrade is the complete fix.`;
    case "upgrade_packages":
      return "Installs the latest distro build of these packages (complete fix when a patched build exists). Previous versions are recorded for rollback.";
    case "nginx_block_multipart":
      return "Partial mitigation — nginx rejects multipart/form-data requests (file uploads stop working). Not a fix.";
    case "set_php_directive":
      return "Partial mitigation — changes one php.ini directive and restarts that PHP SAPI. Never makes the server safe on its own.";
    case "restart_service":
      return "Briefly restarts the service.";
    default:
      return "";
  }
}

export function isActionRecord(v: unknown): v is ActionRecord {
  return !!v && typeof v === "object" && "id" in v && "type" in v && "state" in v && "hostId" in v && "params" in v;
}

/** Tool outputs may be the ActionRecord itself or wrap it ({ action }, { proposal }, ...). */
export function extractAction(output: unknown): ActionRecord | null {
  if (isActionRecord(output)) return output;
  if (output && typeof output === "object") {
    for (const k of ["action", "proposal", "revision", "record", "result"]) {
      const v = (output as Record<string, unknown>)[k];
      if (isActionRecord(v)) return v;
    }
  }
  return null;
}
