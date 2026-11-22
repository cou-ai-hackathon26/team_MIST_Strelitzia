# Prohori

**Agentic exposure management for organizations without a security team.**

Prohori keeps a live inventory of every server, watches vulnerability intelligence (OSV.dev, CISA KEV), and uses **Sentinel**, its AI security analyst, to decide which servers are *actually* exposed to a new CVE — not just which ones report a matching version number. Sentinel emails the security team an incident report, discusses remediation with admins in chat, and applies only allow-listed, human-approved fixes through a hardened host daemon.

> In October 2026 a critical PHP flaw ("PHP2Shell", CVE-2026-109618 / CVE-2026-109619) pushed Bangladesh Bank, six commercial banks and the Ministry of Land offline for up to three days, because nobody could tell quickly which servers were really vulnerable. Prohori answers that question in minutes.

![Prohori overview](docs/images/overview.png)

---

## How it works

```
 ┌─ Asset (Linux server) ──────────────┐         ┌─ Sentinel brain (apps/brain, Bun) ────────────────────┐
 │ prohori-daemon (TypeScript / Bun)   │   WSS   │ WebSocket gateway · SQLite · HTTP API                 │
 │  ├ osquery: packages, ports, config │ ──────▶ │ Mastra scan workflow (fixed steps, AI inside steps)   │
 │  └ allow-listed remediation runner  │ ◀────── │ Mastra chat agent "Sentinel" (tools, memory)          │
 └─────────────────────────────────────┘ outbound│ cron scans · report email · CISA KEV feed            │
                                         only    └──────────────┬──────────────────────┬─────────────────┘
                                                                │ OSV.dev, CISA KEV    │ LLM (Claude Haiku)
                    ┌─ Dashboard (apps/web, Next.js) ───────────┴──────────────────────┘
                    │ Overview · Findings · Reports · Sentinel chat · Approvals ·
                    │ Threat Intelligence · Audit Log · Settings
                    └────────────────────────────────────────────────────────────────
```

1. **Inventory.** A thin daemon on each server wraps osquery and reports exact package builds (including the distro *source* package), listening ports, firewall state and relevant config. It connects **outbound** to the brain; the brain never logs into servers.
2. **Detection.** Every scan matches installed builds against OSV.dev using the distro ecosystem (e.g. `Ubuntu:24.04:LTS`), so backported fixes are recognized.
3. **Triage (Sentinel).** Sentinel reviews every matched CVE and decides which deserve investigation, with a written reason — e.g. a pre-auth remote code execution in a network daemon, as opposed to a local or library-only bug. A floor rule in code always includes CISA KEV and distro-critical CVEs.
4. **Advisory analysis (Sentinel).** For each new CVE, Sentinel reads the advisory sources referenced by the vulnerability record (vendor advisories, distro notices, mailing-list disclosures) and derives a **threat profile**: the affected component, attack vector, preconditions that can be checked on a server, the complete fix, and partial mitigations with their trade-offs. Nothing about any specific CVE or product is hard-coded.
5. **Investigation (Sentinel).** Per affected asset, Sentinel runs read-only checks through the daemon — installed binaries, listeners, services, firewall, allow-listed configuration files — and tests each precondition, citing the checks that support every conclusion. Verdicts: **Exposed**, **Vulnerable · Unreachable**, **Not Affected**.
6. **Code guardrails.** A build the distro reports as patched is always *Not Affected*; a reachability claim without cited evidence, or contradicted by the facts, becomes *Exposed* and is flagged for confirmation; firewall containment is checked against the actual rules. Any override is recorded on the finding.
7. **Remediation plan (Sentinel).** Sentinel ranks fixes from the allow-list (firewall port, package upgrade, nginx upload block, allow-listed configuration directive, service restart) for the specific asset and explains trade-offs. It knows the platform's constraints (for example, Prohori never closes SSH port 22) and plans around them.
8. **Reporting and approval.** New or escalated exposures produce an incident report emailed to the security team. An admin reviews proposed fixes in conversation with Sentinel, optionally has them revised, and approves; every decision is attributed and logged, and every change can be rolled back.

Every finding page shows Sentinel's full investigation: triage reason, threat profile, preconditions with citations, the checks it ran, its conclusion, any guardrail, and the ranked remediation plan.

### Safety model

- **The daemon runs only named osquery queries and allow-listed actions,** validating parameters itself. It never executes arbitrary commands, and refuses to touch port 22.
- **Sentinel can propose but never approve.** There is no approve tool; approval is a human click in an authenticated session, recorded with the admin's name and note.
- **Advisory text is treated as untrusted:** the AI step that reads it has no tools.
- **Every remediation requires human approval.** This cannot be disabled.

---

## Quick start (Docker lab)

### Prerequisites

| Tool | Version |
|---|---|
| [Bun](https://bun.sh) | 1.4+ |
| Docker with Compose | 24+ |
| An Anthropic-compatible LLM endpoint | OpenCode Go (`claude-haiku-5-5`) is the default |

Free ports: **3000** (dashboard), **4400** (brain), **8081 / 8082** (lab web servers), **1025 / 8025** (Mailpit).

### 1. Install and configure

```bash
git clone git@gitlab.com:ahnaf-zamil/prohori.git
cd prohori
cp .env.example .env          # then set OPENCODE_API_KEY
bun run setup                 # installs dependencies and builds the host daemon
```

### 2. Start the lab assets

```bash
bun run targets:up            # bank-web-01, bank-web-02, bank-batch-01, bank-ssh-01 + Mailpit
```

### 3. Start Sentinel and the dashboard (two terminals)

```bash
bun run brain                 # terminal 1 — Sentinel brain on :4400
bun run web:prod              # terminal 2 — dashboard on :3000 (production build)
```

### 4. Verify

```bash
bun run healthcheck
```

Open **http://localhost:3000** and sign in as `zamil` or `nusrat` (password `prohori-admin`, set in `ADMIN_USERS`). Report emails arrive in Mailpit at **http://localhost:8025**.

> Use `bun run web:prod` for demos. The dev server (`bun run web`) works, but hot reload can loop when the dashboard is opened from Windows into WSL.

---

## The lab scenario

All three lab assets report **PHP 8.3.6** — a version-number check flags every one of them. Sentinel shows that only one is an emergency.

| Asset | PHP build | Serving | Sentinel's assessment |
|---|---|---|---|
| bank-web-01 (`web-a`) | `8.3.6-0maysync1` (vulnerable) | nginx + php-fpm on :80 | **Exposed** · Critical · CISA KEV |
| bank-web-02 (`web-b`) | `8.3.6-0ubuntu0.24.04.13` (patched backport) | nginx + php-fpm on :80 | **Not Affected** |
| bank-batch-01 (`batch-c`) | `8.3.6-0maysync1` (vulnerable) | PHP CLI only, nothing listening | **Vulnerable · Unreachable** |

PHP2Shell is **embargoed** until you click **Replay Disclosure** for it in **Settings → Demonstration Controls**, so the live demo shows Sentinel discovering a new CVE on its own.

### Held-out scenario: regreSSHion (generalization check)

A second scenario that no prompt or line of scan code mentions. It exercises everything the PHP2Shell path does not: the CVE is not on CISA KEV and is not distro-critical (so only Sentinel's triage picks it up), the vulnerable service listens on SSH port 22 (which Prohori never firewalls, so Sentinel must plan around it), and its documented mitigation is partial with a denial-of-service trade-off that Sentinel has to find in the advisory.

| Asset | OpenSSH build | Serving | Expected |
|---|---|---|---|
| bank-ssh-01 (`ssh-d`) | `1:9.6p1-3ubuntu13` (vulnerable) | sshd on :22 | **Exposed** · High |
| bank-web-02 (`web-b`) | latest noble-security (patched) | sshd on :22 | **Not Affected** |
| bank-batch-01 (`batch-c`) | `1:9.6p1-3ubuntu13`, client only | no sshd | **Vulnerable · Unreachable** |

### Evaluation

```bash
bun run eval           # replays PHP2Shell 3× and regreSSHion 1× against expected verdicts
bun run prompt-audit   # fails if any prompt or scan code names a specific CVE, product or CVE-specific mitigation
```

The evaluation checks every asset's verdict and priority, that each finding carries an investigation, and that every non-safe finding has a remediation plan. A newly disclosed CVE takes roughly 60–120 s from disclosure to verdict (Sentinel analyses the advisory once and caches the profile).

The full presentation runbook — pre-flight checklist, click-by-click script, talking points and recovery — is in **[docs/DEMO.md](docs/DEMO.md)**.

---

## Configuration

All settings live in the root `.env` (see [`.env.example`](.env.example) for every option).

| Variable | Purpose |
|---|---|
| `OPENCODE_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` | Sentinel's model (Anthropic Messages API format) |
| `BRAIN_PORT`, `BRAIN_API_TOKEN` | Brain port and the shared secret used by the dashboard |
| `SEED_HOSTS` | Pre-enrolled lab assets (`id:name:token`) |
| `DEMO_SCENARIOS`, `DEMO_REPLAY_HOLD` | Replayable disclosures and their CVEs (embargoed until replayed) |
| `SMTP_HOST`, `SMTP_PORT`, `REPORT_FROM`, `DEFAULT_REPORT_EMAILS` | Report delivery |
| `ADMIN_USERS`, `SESSION_SECRET` | Dashboard accounts and session signing |

Scan interval and report recipients can also be changed at runtime in **Settings**.

---

## Commands

| Command | What it does |
|---|---|
| `bun run setup` | Install dependencies and build the daemon binary |
| `bun run targets:up` / `targets:down` | Start / stop the Docker lab assets and Mailpit |
| `bun run targets:reset` | Recreate the lab assets from their images (restores the original PHP builds) |
| `bun run brain` | Run the Sentinel brain |
| `bun run web:prod` | Build and serve the dashboard |
| `bun run web` | Dashboard in development mode |
| `bun run daemon:build` | Rebuild `apps/daemon/bin/prohori-daemon` (restart the lab containers afterwards) |
| `bun run healthcheck` | Pre-flight check of every dependency |
| `bun run eval` | Replay each scenario and score Sentinel's verdicts |
| `bun run prompt-audit` | Verify no CVE- or product-specific knowledge is hard-coded |

---

## Project layout

```
apps/
  daemon/   Host daemon: osquery collection, outbound WebSocket, allow-listed actions with rollback
  brain/    Sentinel: gateway, SQLite, Mastra scan workflow + chat agent, OSV/KEV clients, email, HTTP API
  web/      Next.js dashboard
packages/
  shared/   Contracts shared by all apps: domain types, WebSocket protocol, named queries, actions, API
infra/
  docker-compose.yml   Lab assets (Ubuntu 24.04: nginx/PHP builds, OpenSSH builds) and Mailpit
  targets/             Lab asset image and sample bank site
  vm/install-daemon.sh Daemon installer for real Ubuntu servers (systemd, sudoers allow-list)
scripts/
  healthcheck.ts       Pre-flight check
  eval.ts              Scenario evaluation (expectations in eval-scenarios.json)
  prompt-audit.ts      Guard against hard-coded CVE knowledge
docs/
  DEMO.md       Presentation runbook
  CONTRACTS.md  Internal build contract and design notes
```

## Running on real servers

`infra/vm/install-daemon.sh` installs osquery and the daemon as a systemd service on Ubuntu 24.04, with a dedicated user and a sudoers allow-list limited to the remediation commands. Use **Settings → Add Asset** to generate an enrollment token and the install command, and set `BRAIN_PUBLIC_URL` so the command points at a brain address the server can reach. This path is written but has not yet been exercised end to end.

## Tech stack

TypeScript and Bun throughout · Mastra (agent, tools, workflow, memory) · Claude Haiku via OpenCode Go · Next.js 16 + Tailwind CSS 4 · SQLite / libSQL · osquery · Docker · Mailpit · OSV.dev and CISA KEV.
