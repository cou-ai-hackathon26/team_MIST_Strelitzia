// HTTP API exposed by the brain (Bun.serve on BRAIN_PORT, default 4400) and consumed by the web dashboard.
// All routes are under /api and require header `Authorization: Bearer <BRAIN_API_TOKEN>`.
// The web proxy also sends `X-Prohori-Actor: <admin username>` (from the session) on every request; the brain
// records it as `actor` on audit events and as decidedBy/rolledBackBy on actions. Missing header → actor "unknown".
// Admin accounts (MVP): env ADMIN_USERS="rahim:pass1,nusrat:pass2" checked by the web app only.
// The browser never talks to the brain directly: the Next.js app proxies /api/* to the brain and adds the token,
// after checking the admin session cookie. JSON in/out unless noted. Errors: { error: string } with 4xx/5xx.

import type {
  ActionRecord, AuditEvent, Finding, FindingStatus, HostSummary, InventorySnapshot, Report, Settings, WildCve,
} from "./domain";

export interface ScanState {
  running: boolean;
  lastStartedAt: string | null;
  lastFinishedAt: string | null;
  nextRunAt: string | null;
  lastResult: { newFindings: number; changedFindings: number; reportsSent: number; error?: string } | null;
}

// GET /api/status
export interface StatusResponse {
  hosts: HostSummary[];
  scan: ScanState;
  totals: Record<FindingStatus, number>;
  pendingActions: number;
  inKevExposed: number;           // exposed findings that are on CISA KEV
  recentEvents: AuditEvent[];     // last 15
  demo: { replayHeld: string[]; injected: string[] }; // see POST /api/demo/inject
}

// GET /api/hosts                 -> HostSummary[]
// GET /api/hosts/:id             -> HostDetailResponse
export interface HostDetailResponse {
  host: HostSummary;
  inventory: InventorySnapshot | null;
  findings: Finding[];
}

// POST /api/hosts/enroll  body: { name: string } -> EnrollResponse   (creates host id + token)
export interface EnrollResponse {
  hostId: string;
  token: string;            // shown once
  installCommand: string;   // one-liner for the VM (Phase 5); for docker targets the compose file sets env vars
}

// GET /api/findings?status=exposed&hostId=web-a -> Finding[]  (sorted: priority, then status)
// GET /api/findings/:id                         -> Finding
// GET /api/reports                              -> Report[] (newest first)
// GET /api/reports/:id                          -> Report

// POST /api/scan  -> { started: boolean; scan: ScanState }   (no-op if already running)

// GET /api/settings -> Settings
// PUT /api/settings body: Partial<Settings> -> Settings      (reschedules cron if interval changed)

// GET /api/wild -> WildCve[]   (recent CISA KEV additions, newest first, max 30)

// GET  /api/actions?state=pending&hostId=  -> ActionRecord[]
// GET  /api/actions/:id                    -> ActionRecord
// POST /api/actions/:id/approve  body: { note?: string; threadId?: string } -> ActionRecord
//      (human-only; only from state pending; sends to daemon; approved→running→applied|failed; audit actor+note+threadId)
// POST /api/actions/:id/reject   body: { note?: string; threadId?: string } -> ActionRecord
// POST /api/actions/:id/rollback body: { note?: string } -> ActionRecord   (only if applied)
// Revisions are created by the chat agent's `reviseProposal` tool (never by approve): new pending action with
// supersedes=<old>, old one → state "superseded" + supersededBy. Audit "action_revised".

// GET /api/audit?limit=100&hostId=&kind= -> AuditEvent[] (newest first)   — the "Event log" tab

// Demo replay of the PHP2Shell disclosure (Oct 21 2026):
// The brain holds back CVE ids listed in env DEMO_REPLAY_HOLD (default "CVE-2026-109618,CVE-2026-109619")
// — scans ignore them (and their aliases, e.g. UBUNTU-CVE-*) until injected.
// POST /api/demo/inject body: { cveIds?: string[] }  -> { injected: string[] }  (releases them; next scheduled scan finds them)
// POST /api/demo/reset                               -> { ok: true }  (re-holds them, deletes their findings/reports/actions)

// GET /api/chat/threads/:threadId/messages -> UIMessage[]  (to reopen a discussion, e.g. from an action's threadId)
// POST /api/chat
//   body: { messages: UIMessage[]; threadId?: string; actionId?: string }
//   actionId = "Review with Prohori" context: the agent is told which pending action/finding is being discussed
//   (inject the action + finding details into the system context for that request; persist action.threadId).   (AI SDK UIMessage format, as sent by useChat + DefaultChatTransport)
//   response: AI SDK UI message stream (SSE) — must work with `useChat` from @ai-sdk/react.
//   Tool calls must appear as tool parts so the UI can render them.

export type {
  ActionRecord, AuditEvent, Finding, HostSummary, InventorySnapshot, Report, Settings, WildCve,
};
