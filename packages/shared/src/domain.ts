// Core domain types shared by daemon, brain and web.
// Timestamps are ISO-8601 strings everywhere.

export type HostStatus = "online" | "offline";

export interface HostSummary {
  id: string;              // stable id, e.g. "web-a"
  name: string;            // display name, e.g. "bank-web-01"
  status: HostStatus;
  lastSeen: string | null; // last heartbeat/inventory
  os: string | null;       // e.g. "Ubuntu 24.04.3 LTS"
  daemonVersion: string | null;
  findingCounts: Record<FindingStatus, number>;
  /** Total raw OSV matches for this host's packages — what a naive scanner would alert on. */
  rawMatchCount: number;
}

/** One installed OS package as reported by osquery `deb_packages` (or rpm_packages). */
export interface InstalledPackage {
  name: string;     // binary package, e.g. "php8.3-fpm"
  version: string;  // full distro version, e.g. "8.3.6-0maysync1"
  source: string;   // source package, e.g. "php8.3" — OSV Ubuntu/Debian ecosystems match on THIS
  arch: string;
}

export interface ListeningPort {
  port: number;
  protocol: "tcp" | "udp";
  address: string;   // bound address, e.g. "0.0.0.0", "127.0.0.1", "::"
  process: string;   // process name owning the socket, e.g. "nginx"
  pid: number;
}

export interface OsInfo {
  name: string;       // "Ubuntu"
  version: string;    // "24.04.3 LTS (Noble Numbat)"
  versionId: string;  // "24.04"
  codename: string;   // "noble"
  platform: string;   // "ubuntu"
}

/** A port closed by a Prohori-managed firewall rule on the host. */
export interface FirewallRule {
  port: number;
  protocol: "tcp" | "udp";
  state: "closed";
  managedBy: "prohori";
  actionId: string | null; // action that created it, if known
}

/** Full inventory snapshot sent by the daemon. */
export interface InventorySnapshot {
  collectedAt: string;
  hostname: string;
  os: OsInfo;
  packages: InstalledPackage[];
  listeningPorts: ListeningPort[];
  processes: { name: string; path: string; pid: number }[];
  /** Firewall state: ports closed by Prohori rules. A closed port means services on it are NOT network-reachable. */
  firewall: { available: boolean; closedPorts: FirewallRule[] };
  /** Selected config values, key = "<file>:<directive>", e.g. "/etc/php/8.3/fpm/php.ini:memory_limit" */
  config: Record<string, string>;
}

/**
 * Exposure verdict for a (host, CVE) pair.
 * - exposed: vulnerable build AND reachable over the network → act now
 * - vulnerable_not_exposed: vulnerable build but no network path (e.g. CLI-only) → upgrade, normal priority
 * - not_affected: installed build is not vulnerable (e.g. distro backported fix) or product absent
 */
export type FindingStatus = "exposed" | "vulnerable_not_exposed" | "not_affected";

export type Priority = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  hostId: string;
  cveId: string;             // primary id, e.g. "CVE-2026-109618"
  aliases: string[];
  title: string;
  status: FindingStatus;
  priority: Priority;
  confidence: "high" | "medium" | "low";
  needsConfirmation: boolean; // true when the match came from AI-parsed advisory text
  inKev: boolean;
  cvss: string | null;        // vector or score string
  package: { name: string; installedVersion: string; fixedVersion: string | null } | null;
  /** What a naive version-number check would conclude (for the "scanner flags both" contrast). */
  naiveVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  rationale: string;          // AI-written, evidence-based explanation (markdown)
  mitigations: string[];      // ordered; first = complete fix if one exists
  evidence: Record<string, string>; // e.g. { "installed": "...", "listening": "0.0.0.0:80 nginx" }
  firstSeen: string;
  updatedAt: string;
  reportId: string | null;
  /** Sentinel's investigation for this asset/CVE (absent for findings created before investigations existed). */
  investigation?: Investigation | null;
}

/** Per-CVE analysis Sentinel derives from the advisory text (cached; never hard-coded per CVE). */
export interface ThreatProfile {
  cveId: string;
  summary: string;                 // one-paragraph plain-English description
  component: string;               // affected component, e.g. "the PHP web runtime (FPM/Apache module)"
  attackVector: "network" | "adjacent" | "local" | "physical" | "unknown";
  preconditions: { id: string; text: string; howToCheck: string }[]; // checkable on a host
  completeFix: string;             // e.g. "upgrade <source package> to the distro fixed build"
  partialMitigations: { text: string; tradeoff: string }[];
  exploitedInWild: boolean;
  sources: string[];               // URLs/ids the profile was derived from
  generatedAt: string;
}

export interface InvestigationStep {
  tool: string;                    // e.g. "runHostQuery", "readConfigFile"
  input: Record<string, unknown>;
  summary: string;                 // what the result showed (short)
  ref: string;                     // citation id, e.g. "S3"
}

export interface Investigation {
  triage: { decidedBy: "rule" | "sentinel"; reason: string };
  profile: Pick<ThreatProfile, "summary" | "component" | "attackVector" | "completeFix"> | null;
  preconditions: { id: string; text: string; result: "met" | "not_met" | "unknown"; evidence: string[]; note: string }[];
  steps: InvestigationStep[];
  conclusion: string;              // Sentinel's conclusion before code guardrails
  guardrail: string | null;        // set when code overrode or downgraded Sentinel's conclusion, and why
  remediationPlan: { kind: "containment" | "fix" | "partial"; summary: string; tradeoff: string; actionType: string | null; params: Record<string, unknown> | null }[];
}

export interface Report {
  id: string;
  createdAt: string;
  title: string;
  findingIds: string[];
  markdown: string;     // full report body
  emailedTo: string[];  // empty if not emailed
  emailedAt: string | null;
}

export type ActionState = "pending" | "approved" | "running" | "applied" | "failed" | "rejected" | "rolled_back" | "superseded";

export interface ActionRecord {
  id: string;
  hostId: string;
  findingId: string | null;
  type: import("./actions").ActionType;
  params: Record<string, unknown>;
  reason: string;          // why the AI proposed it
  state: ActionState;
  proposedBy: "agent" | "user";
  createdAt: string;
  decidedAt: string | null;
  decidedBy: string | null;     // admin username who approved/rejected (from X-Prohori-Actor)
  decisionNote: string | null;  // optional note typed by the admin when deciding
  threadId: string | null;      // chat thread where this action was discussed/revised/approved
  supersedes: string | null;    // id of the earlier proposal this one revises
  supersededBy: string | null;  // set when a newer revision replaces this pending proposal
  rolledBackBy: string | null;
  result: { ok: boolean; diff: string; output: string } | null;
  /**
   * Live progress after a human decision, for the dashboard:
   * applying / rolling_back → daemon working; rechecking → daemon reported, Sentinel re-scanning the host;
   * done → a scan that started after the daemon's result has finished (verdicts are current). null = never started.
   */
  progress: { phase: "applying" | "rolling_back" | "rechecking" | "done"; since: string; resultAt: string | null } | null;
}

export interface Settings {
  reportEmails: string[];
  scanIntervalSec: number;   // demo default 45
  wildRefreshSec: number;    // default 900
  cveScanEnabled: boolean;   // demo gate: no CVE scanning/findings until switched on (reset switches it off)
}

export interface AuditEvent {
  id: string;
  at: string;
  kind: "scan_started" | "scan_finished" | "finding_new" | "finding_changed" | "report_sent"
      | "action_proposed" | "action_approved" | "action_rejected" | "action_applied" | "action_failed"
      | "action_rolled_back" | "host_online" | "host_offline" | "inventory_changed" | "demo_inject"
      | "settings_changed" | "wild_refreshed" | "error"
      | "cve_discovered"       // a CVE newly relevant to our inventory (once per CVE per scan)
      | "vulnerable_detected"  // a host judged exposed / vulnerable_not_exposed
      | "report_generated"     // report saved (report_sent = email delivered)
      | "action_revised"       // a pending proposal superseded by a revision (usually from chat)
      | "judgment_requested"   // an admin asked Sentinel to judge an advisory URL
      | "judgment_done"        // a judgment finished (or failed)
      | "judgment_tracked"     // a judgment was turned into findings ("Track as findings")
      | "login";
  message: string;
  actor: string;          // "prohori" for the system/agent, "daemon:<hostId>" for daemon results, else admin username
  hostId?: string;
  cveId?: string;
  data?: Record<string, unknown>;
}

/** Card for the "CVEs in the wild" page (from CISA KEV). */
export interface WildCve {
  cveId: string;
  vendorProject: string;
  product: string;
  name: string;
  dateAdded: string;
  shortDescription: string;
  knownRansomwareCampaignUse: string; // "Known" | "Unknown"
  dueDate: string;
  affectsHosts: string[]; // host ids where we have a finding with status exposed|vulnerable_not_exposed
}

// ---------------------------------------------------------------- advisory judgments ("Judge an advisory" mode)
// The admin hands Sentinel an advisory URL (usually from chat). Sentinel judges it against every host WITHOUT the
// scan feed: the page is the source of truth for what/how; distro records (OSV UBUNTU-/DEBIAN-<CVE>), when a CVE id
// is known and they exist, decide whether the installed build is patched. Stored separately from findings until the
// admin clicks "Track as findings". Bypasses DEMO_IGNORE_CVES (explicit admin request).

export type JudgmentState = "queued" | "fetching" | "analysing" | "investigating" | "done" | "failed";

export interface JudgmentHost {
  hostId: string;
  hostName: string;
  sourcePackage: string;           // installed source package the advisory's product was matched to
  installedVersion: string;        // full distro version
  upstreamVersion: string;
  binaries: string[];
  /** how the advisory's product was matched to this source package, e.g. 'exact source package "cyrus-sasl2"' */
  packageMatch: string;
  /** whether the installed build is patched, and which source decided it */
  fixStatus: {
    source: "distro_record" | "advisory_only";
    verdict: "vulnerable" | "not_vulnerable" | "unknown";
    fixedVersion: string | null;   // distro fixed build (distro_record) or upstream fixed version (advisory_only), if any
    detail: string;                // one line, e.g. "Ubuntu record UBUNTU-CVE-…: no fixed build released for Ubuntu:24.04:LTS"
  };
  /** what a version-number-only check concludes (the contrast shown on the judgment page) */
  naiveVerdict: "vulnerable" | "not_vulnerable" | "unknown";
  status: FindingStatus;
  priority: Priority;
  confidence: "high" | "medium" | "low";
  needsConfirmation: boolean;
  rationale: string;               // markdown, cites S1…
  reachability: string;
  exposedPorts: string[];          // e.g. ["80/tcp"]
  mitigations: string[];
  investigation: Investigation;
}

export interface AdvisoryJudgment {
  id: string;                      // "jdg_…"
  url: string;
  focus: string | null;            // optional admin hint when a page covers several bugs ("the SRP bypass")
  requestedBy: string;
  threadId: string | null;         // chat thread that requested it
  createdAt: string;
  updatedAt: string;
  state: JudgmentState;
  progress: string;                // human-readable current step, e.g. "Investigating bank-web-01 (2/4)"
  error: string | null;
  advisory: {
    cveId: string | null;          // primary CVE id of THE judged vulnerability (admin-supplied wins), null if none known
    otherIds: string[];            // other ids seen on the page (CVE/GHSA/…) — may belong to other bugs
    title: string;
    product: string;
    sourcePackageGuess: string;
    affectedRanges: { introduced?: string; fixed?: string; lastAffected?: string }[];
    fixedVersions: string[];       // upstream fixed versions stated by the advisory (empty = none stated)
    fixAvailable: "yes" | "no" | "unknown"; // per the advisory text
    conditions: string[];
    distroRecords: string[];       // OSV distro record ids consulted (empty = advisory-only)
    onIgnoreList: boolean;         // the CVE is in DEMO_IGNORE_CVES (scans never looked at it)
  } | null;
  profile: ThreatProfile | null;
  hosts: JudgmentHost[];           // hosts with a matching installed package (investigated)
  notInstalledOn: { hostId: string; hostName: string }[];
  summary: string | null;          // one-paragraph verdict for chat/cards
  tracked: { at: string; by: string; cveId: string; findingIds: string[]; proposedActions: number } | null;
}
