# Prohori (প্রহরী) — the sentinel

An always-on AI security platform. Its AI agent is called **Sentinel** (code: `apps/brain`). A small daemon on each server reports exactly what software runs there (via osquery). Sentinel watches CVE databases (OSV.dev, CISA KEV), decides which servers are **actually** exposed, emails the IT team a report, lets admins discuss fixes with the agent in chat, and applies only allowlisted fixes after a named admin approves.

Design and contracts: `docs/CONTRACTS.md`. Shared types: `packages/shared/`.

## Run it (Docker dev setup)

Prereqs: Bun ≥ 1.4, Docker. Copy `.env.example` → `.env` and set `OPENCODE_API_KEY`.

```bash
bun install
bun run daemon:build          # builds apps/daemon/bin/prohori-daemon
bun run targets:up            # 3 demo servers + Mailpit (docker compose)
bun run brain                 # Sentinel (the brain) on :4400  (separate terminal)
cd apps/web && bun run build && bun run start   # dashboard on :3000 (production mode; dev mode HMR loops when browsed from Windows→WSL)
```

- Dashboard: http://localhost:3000 — users from `ADMIN_USERS` (dev: `rahim` / `nusrat`, password `prohori-admin`)
- Mailpit (report emails): http://localhost:8025
- Demo sites: bank-web-01 http://localhost:8081 · bank-web-02 http://localhost:8082

Port 4000 on the dev machine is used by another container, hence Sentinel on **4400**.

## Demo servers

| Server | PHP build | Serving | Correct verdict |
|---|---|---|---|
| bank-web-01 (`web-a`) | `8.3.6-0maysync1` (vulnerable) | nginx + php-fpm on :80 | **exposed** (critical, KEV) |
| bank-web-02 (`web-b`) | `8.3.6-0ubuntu0.24.04.13` (patched backport) | nginx + php-fpm on :80 | **not affected** |
| bank-batch-01 (`batch-c`) | `8.3.6-0maysync1` (vulnerable) | CLI only, nothing listening | **vulnerable, not exposed** |

All three report "PHP 8.3.6"; a version-number scanner flags all three. All three have fixes (Tier 2) enabled; every fix still needs a named admin to approve it.

## Demo script (~90 s)

1. **Overview**: three servers online, hundreds of raw "naive scanner" alerts, nothing urgent (PHP2Shell is held back — the replay starts on Oct 20).
2. **Settings → Demo panel → "Inject PHP2Shell"** (replays the Oct 21 disclosure). Within one scan interval (~45 s), with nobody touching anything, Sentinel discovers it: red banner on bank-web-01, the "Version scanner vs Sentinel" table shows 3 vs 1.
3. **Mailpit**: the report email to it-security@ and soc@.
4. **Ask Sentinel**: "Why is bank-web-02 safe?" — watch the tool calls.
5. **Approvals → Review with Sentinel** on "Close port 80/tcp on bank-web-01": ask "can we avoid taking the site offline?" → the agent revises the proposal (or keep the firewall) → **Approve** with a note.
6. The daemon applies it; next scan downgrades bank-web-01 to *vulnerable, not exposed* (contained, still upgrade). **Event log** shows who approved what, with the note and the discussion link.
7. Roll back from Approvals → back to exposed.

**Reset between rehearsals:** Settings → "Reset demo". It rolls back every fix still applied to the servers (PHP upgrades, firewall rules, upload blocks, php.ini edits) through the daemons, re-holds PHP2Shell, and clears its findings, reports and open proposals. Give the rollbacks ~10–60 s before injecting again.

If the dashboard shows **"Demo check: no server is vulnerable…"** after an inject, the servers were patched outside a fix Sentinel can still roll back (e.g. records already deleted). Rebuild the demo servers from their images:

```bash
bun run targets:reset    # recreates target-a/b/c with their original PHP builds
```

## Layout

- `apps/daemon` — TypeScript host daemon (Bun binary): osquery named queries, outbound WebSocket, allowlisted actions (`firewall_port`, `upgrade_packages`, `nginx_block_multipart`, `set_php_directive`, `restart_service`) with rollback. Never runs arbitrary commands.
- `apps/brain` — **Sentinel**, the AI agent server (Bun): WebSocket gateway, SQLite, Mastra scan workflow + chat agent (Claude Haiku 5.5 via OpenCode Go), OSV/KEV clients, cron, email, HTTP API.
- `apps/web` — Next.js dashboard (Overview, Findings, Reports, Ask Sentinel, Approvals, CVEs in the wild, Event log, Settings, Hosts).
- `infra/` — Docker targets + Mailpit; `infra/vm/install-daemon.sh` for real Ubuntu VMs (not yet tested).
