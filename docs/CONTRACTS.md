# Prohori — Build Contracts (read this first)

Prohori: an always-on agent that keeps a live inventory of an organization's servers (via a host daemon wrapping osquery), watches CVE databases, decides which servers are *actually* exposed, emails a per-server report, lets an admin chat with the agent, and (opt-in) applies human-approved fixes.

**Source of truth for types:** `packages/shared/src/*` (import as `@prohori/shared`). Do not redefine these types elsewhere. If you believe a contract must change, make the smallest change in `packages/shared`, and list it explicitly in your final report.

## Repo layout & ownership

| Path | Owner | What |
|---|---|---|
| `packages/shared/` | lead | contracts: domain types, WS protocol, named queries, actions, HTTP API |
| `apps/daemon/` | infra/daemon agent | TypeScript daemon (Bun), compiled to `apps/daemon/bin/prohori-daemon` |
| `infra/` | infra/daemon agent | docker targets A/B/C + MailHog (`infra/docker-compose.yml`) |
| `apps/brain/` | brain agent | Bun HTTP+WS server, Mastra agent/workflow/tools, SQLite, cron, email |
| `apps/web/` | web agent | Next.js dashboard (UI only; proxies `/api/*` to brain) |
| `docs/` | lead | docs |

Never edit another agent's directory. Root `package.json`/`bun.lock`: add deps only with `bun add <pkg>` run **inside your own app dir**; if the lockfile is busy, wait a few seconds and retry.

## Runtime topology (dev)

```
docker: target-a (web-a), target-b (web-b), target-c (batch-c), mailhog
   each target runs osquery + prohori-daemon → ws://host.docker.internal:4400/agent
host (WSL): brain  :4400  (HTTP /api/* + WS /agent)       bun run brain
            web    :3000  (Next.js, proxies /api → brain)  bun run web
mailhog: SMTP 127.0.0.1:1025, UI http://127.0.0.1:8025
```

Env lives in repo-root `.env` (see `.env.example`). Brain loads it via `bun --env-file=../../.env`. Web reads `BRAIN_URL`, `BRAIN_API_TOKEN`, `ADMIN_PASSWORD`, `SESSION_SECRET` (configure Next to load the root `.env`, e.g. in `next.config.ts` via `process.loadEnvFile` or dotenv-style loading).

## The demo scenario (everything is built to make this work, truthfully)

PHP2Shell = CVE-2026-109618 + CVE-2026-109619 (published 2026-10-21; on CISA KEV; CVSS 4.0 AV:N/AC:H/AT:P). Affected upstream: PHP < 8.2.35, 8.3.x < 8.3.36, 8.4.x < 8.4.27, 8.5.x < 8.5.12. **Upgrade is the only complete fix.** Partial mitigations only: `memory_limit=-1` (incomplete), lower `post_max_size`/`max_input_nesting_level`/input limits, block multipart at the frontend if uploads aren't needed. **Never claim a php.ini setting makes a server safe.**

Ubuntu fixed it by backport without changing the headline version:

| Target | Host id | Name | PHP build (`php8.3-*`) | Serving | Correct verdict |
|---|---|---|---|---|---|
| A | `web-a` | bank-web-01 | `8.3.6-0maysync1` (noble release pocket, vulnerable) | nginx + php8.3-fpm on 0.0.0.0:80, an upload form at `/upload.php` | **exposed** (critical, KEV) |
| B | `web-b` | bank-web-02 | `8.3.6-0ubuntu0.24.04.13` (noble-security, patched) | same nginx + php-fpm on 0.0.0.0:80 | **not_affected** — same "PHP 8.3.6" banner, but patched build |
| C | `batch-c` | bank-batch-01 | `8.3.6-0maysync1` (vulnerable) | `php8.3-cli` only, no web server, nothing listening | **vulnerable_not_exposed** (upgrade, normal priority) |

A naive version check ("8.3.6 < 8.3.36") flags all three. Prohori must explain why only A is an emergency.

Verified data facts:
- OSV `POST https://api.osv.dev/v1/query` with `{"version":"8.3.6-0maysync1","package":{"name":"php8.3","ecosystem":"Ubuntu:24.04:LTS"}}` returns 56 vulns incl. `UBUNTU-CVE-2026-109618` and `UBUNTU-CVE-2026-109619`; with `8.3.6-0ubuntu0.24.04.13` returns 1 vuln and **no** PHP2Shell. OSV Ubuntu/Debian ecosystems match on the **source** package name (`php8.3`), so the daemon reports `source` per package. Ecosystem string = `Ubuntu:<versionId>:LTS` for LTS releases (`Ubuntu:24.04:LTS`).
- `GET https://api.osv.dev/v1/vulns/CVE-2026-109618` has upstream ranges only (GIT + `database_specific.extracted_events` CPE ranges), summary "RCE via OOM corruption"; `UBUNTU-CVE-2026-109618` lists Ubuntu fixed versions (24.04 php8.3 fixed `8.3.6-0ubuntu0.24.04.13`).
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (fields `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, knownRansomwareCampaignUse, dueDate`). Both PHP2Shell CVEs are listed.
- NVD is flaky — never required.

**Replay mode:** CVE ids in `DEMO_REPLAY_HOLD` (and their aliases like `UBUNTU-CVE-…`, `GHSA-…`) are ignored by scans until `POST /api/demo/inject`. Then the next scheduled scan "discovers" PHP2Shell as new → findings → report email. `POST /api/demo/reset` re-holds them and deletes their findings/reports/actions.

## LLM (verified working)

OpenCode Go, Anthropic-format endpoint, model `claude-haiku-5-5`. Requires headers `x-opencode-session` (stable per conversation/scan run) and a custom `User-Agent`.

```ts
import { createAnthropic } from "@ai-sdk/anthropic";
const anthropic = createAnthropic({
  baseURL: process.env.LLM_BASE_URL,        // https://opencode.ai/inference/go/anthropic/v1
  apiKey: process.env.OPENCODE_API_KEY,
  headers: { "x-opencode-session": sessionId, "User-Agent": process.env.LLM_USER_AGENT! },
});
// Mastra: new Agent({ id, name, instructions, model: anthropic(process.env.LLM_MODEL!), tools })
// agent.generate(prompt) ; structured: agent.generate(prompt, { structuredOutput: { schema } }) → result.object
```
Smoke-tested: Mastra 1.83 Agent + createTool tool call + structuredOutput all work.

Mastra docs: MCP server `mastra-docs` (if available in your session) or the bundled docs at `apps/brain/node_modules/@mastra/core/dist/docs/` (`SKILL.md`, `references/`). Mastra's API changes often — check docs/types before using an API.

## Firewall mitigation (PRIMARY demo action)
`firewall_port {port, protocol, state: closed|open}`: the daemon adds or removes an iptables INPUT DROP/REJECT rule tagged with comment `prohori` (it only ever touches rules carrying that tag; port 22 is refused). Inventory reports `firewall.closedPorts`; query `firewall_rules`. Docker targets need `cap_add: [NET_ADMIN]` + iptables installed.
Brain reachability MUST honour it: a service whose port is closed by a Prohori rule is NOT network-reachable. Demo loop: PHP2Shell found → A exposed/critical → agent auto-proposes `firewall_port {port:80, protocol:"tcp", state:"closed"}` (immediate containment; takes that one site offline) and, separately, `upgrade_packages` (the complete fix) → human approves the firewall action → daemon closes 80 → inventory refresh → rescan → A becomes `vulnerable_not_exposed` (rationale: contained by firewall, still upgrade) → rollback re-opens 80 → A exposed again.

## Safety rules (non-negotiable; also pitch material)
1. Daemon accepts only `QUERY_NAMES` and `ActionParams` (re-validated locally). No raw SQL/shell from the network.
2. The AI can only **propose** actions (`state: "pending"`). There is **no approve tool**. Approval = `POST /api/actions/:id/approve` from the dashboard.
3. Advisory text is untrusted: the AI step that parses advisory text has **no tools**.
4. If evidence is missing/uncertain, the verdict errs toward the more severe status and sets `needsConfirmation`.
5. Reports say "upgrade is the only complete fix" for PHP2Shell; partial mitigations are labelled partial.

## Done = demo-able
`docker compose up` targets → `bun run brain` → `bun run web` → login → Overview shows 3 hosts online with inventory → baseline scan has no PHP2Shell (held) → click "Inject PHP2Shell" (demo panel) → within one scan interval: A exposed/critical, B not_affected, C vulnerable_not_exposed, each with rationale + naive-vs-actual contrast → report email visible in MailHog → chat "why is bank-web-02 safe?" calls tools live → (Tier 2) propose fix for A → Approve → daemon upgrades php8.3 → rescan → A not_affected → rollback works.
