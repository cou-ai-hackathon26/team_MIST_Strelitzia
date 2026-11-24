# Prohori — Demo Runbook

A step-by-step guide for presenting Prohori live: **Part A** (Sentinel discovers a CVE from the feeds and drives the fix, about 3 minutes) and **Part B** (the Advisory Judge: Sentinel judges a brand-new advisory no scan has seen, about 2 minutes). Either part works on its own.

---

## 1. Before you present (T–30 minutes)

Run everything in **your own terminals** so nothing stops mid-demo.

```bash
cd prohori
bun run targets:up        # lab assets + Mailpit
bun run brain             # terminal 1
bun run web:prod          # terminal 2
bun run healthcheck       # must end with "All checks passed. Ready to present."
```

`.env` must list the Advisory Judge demo CVEs in `DEMO_IGNORE_CVES` (see `.env.example`), so no scan reports them before Part B:

```
DEMO_IGNORE_CVES=CVE-2026-129483,CVE-2023-54419,CVE-2026-123007,CVE-2026-123633
```

Then in the browser:

1. Open **http://localhost:3000**, sign in as `nusrat` / `prohori-admin`.
2. **Rehearse once, then reset:** click **Allow CVE Scan** (Settings → Demonstration Controls), let the scan finish, then **Reset Environment**. Threat profiles are cached across resets, so the on-stage scan is faster. A reset clears findings, reports, approvals, judgments, chats and the event log, recreates the lab servers (~30–45 s) and switches CVE scanning **off**.
3. **Overview**: four assets **Online**, none flagged *cannot be assessed*, no critical banner, *Recent Detections* empty.
4. Open **http://localhost:8025** (Mailpit) in a second tab and clear old messages.
5. Keep a tab with **Approvals** open, and have the chat prompts below ready to paste.

**Network:** Sentinel needs internet access for OSV.dev, CISA KEV, advisory pages and the LLM. Have a phone hotspot ready. Record one clean run as a backup video.

---

## 2. Part A — Sentinel discovers a CVE and drives the fix

### Scene 1 — The problem (30 s)

*Overview page.*

> "In October, PHP2Shell forced Bangladesh Bank and six banks offline for up to three days. Not because they were all hacked — because nobody could tell which servers were really vulnerable, so they shut everything down. These are our bank servers. Three of them report PHP 8.3.6, which is below the fixed upstream version. A version check would say all three are vulnerable."

### Scene 2 — Sentinel discovers it (45 s)

*Settings → Demonstration Controls → **Allow CVE Scan**, then back to Overview.*

> "From here nobody touches Prohori. Sentinel checks every server against today's real data from OSV and CISA."

Within ~35–60 s:

- The **Critical exposure detected** banner appears (on bank-web-01 — and bank-ssh-01 for regreSSHion).
- **Recent Detections** shows: bank-web-01 **Exposed**, bank-batch-01 **Vulnerable · Unreachable**, bank-web-02 **Not Affected** (and regreSSHion on bank-ssh-01).

> "Same version number, three different realities. bank-web-02 runs Ubuntu's patched build — the fix was backported without changing the version. bank-batch-01 has the vulnerable build but only runs PHP from the command line; nothing reaches it from the network. Only bank-web-01 is an emergency."

**Show the work (30 s):** click **Investigate** on the banner. Scroll through *Sentinel's Investigation*: the threat profile derived from the advisory, the preconditions with citations (`S1`, `S2`…), and the checks it ran on bank-web-01.

> "None of this is hard-coded. Sentinel read PHP's own advisory, worked out what makes this exploitable, checked those conditions on each server, and cited its evidence. Code guardrails sit on top: a patched build is always safe, and an uncited claim is never trusted."

### Scene 3 — The report (20 s)

*Switch to the Mailpit tab.* The report arrives about a minute after the verdicts (it is written in the background, so the approvals don't wait for it).

> "The security team has the incident report: what the CVE is, that it's being exploited in the wild, exactly which server is exposed and why, and the fix."

### Scene 4 — Ask Sentinel (30 s)

*Sentinel page, paste:*

`Why is bank-web-02 not affected by PHP2Shell?`

### Scene 5 — Human-approved remediation (45 s)

*Approvals → on "Close port 80/tcp on bank-web-01" click **Review with Sentinel**, then paste:*

`We can't take the website down during business hours. What are our options?`

> "Sentinel proposed immediate containment and the real fix. The admin pushes back, Sentinel explains the trade-off — and if asked, revises the proposal. It can never approve anything itself."

Click **Approve** on the pinned proposal, add a note (e.g. `Contain now, upgrade tonight`), **Confirm Approval**.

> "The daemon applies exactly this change — nothing else is possible — and Sentinel re-checks just that server."

*Remediation applied — Sentinel is re-assessing…* resolves in ~25 s: bank-web-01 moves from **Exposed** to **Vulnerable · Unreachable** (firewall) or **Not Affected** (upgrade).

### Scene 6 — Accountability (15 s)

*Audit Log.*

> "Every step is attributed: what Sentinel detected, the report that went out, and that nusrat approved the change, with her note and a link to the discussion."

---

## 3. Part B — Judge a brand-new advisory (the Advisory Judge)

Works with CVE scanning **off** (best straight after a **Reset Environment**). Both CVEs below are on the scan ignore list, so the scan has never looked at them.

### Scene B1 — Hand Sentinel an advisory (30 s)

*Sentinel page, paste:*

`Sentinel, judge this new advisory against our servers: https://www.vulncheck.com/advisories/nginxwebui-3.0.0-3.5.8-authentication-bypass-rce-via-runcmd`

> "This advisory just came out. No scan feed lists it against our servers yet. Instead of waiting, we ask Sentinel to judge it now."

A live **Advisory Judgment** card appears in the chat and moves through *fetching → analysing → investigating* (about 1 minute).

### Scene B2 — The verdict (45 s)

*Click **Open Judgment**.*

- **Version-only check: 1 vulnerable → Sentinel: 1 Exposed.** bank-web-01 runs `nginxwebui 3.5.7` with its admin UI listening on `:8080`; the other three servers don't have it.
- **Critical**, because the advisory reports exploitation in the wild (the rationale says so; it is not on CISA KEV).
- Expand bank-web-01: the cited checks (package files, processes, services, firewall) and the plan — **close 8080/tcp** as containment; upgrading to 3.5.8 is a vendor release, not a distro package, so it is advice.
- *Pending confirmation*: there is no distro record for this application, so the build check rests on the advisory's own version range. Say it — it is Sentinel being honest about weaker evidence.

> "Sentinel read the advisory, found the one server running the vulnerable product, proved it is reachable, and planned a containment we can apply now."

### Scene B3 — Act on it (45 s)

Click **Track as Findings** → 1 critical finding and the proposal **close 8080/tcp on bank-web-01** appear. *Approvals →* **Approve** it.

Within ~25 s the targeted re-check moves bank-web-01 to **Vulnerable · Unreachable**, citing the new firewall rule.

**Alternative advisory — the "don't panic" story:** `https://www.vulncheck.com/advisories/cyrus-sasl-through-2.1.28-srp-authentication-bypass-via-plugins-srp-c` (Cyrus SASL pre-auth bypass, no fix released anywhere). A version check flags **all four** servers; Sentinel shows **none** is reachable: the library is only a dependency, nothing loads it, nothing listens, and the SRP plugin isn't even installed. Track creates 4 findings and **no** emergency changes — and says why.

**Closing line:**

> "From disclosure to the right team holding the fix — in minutes, not the 43-day industry average. Even before the feeds catch up. And for organizations that can't afford a security team, Sentinel is that team."

---

## 4. Timing reference

| Step | Typical time |
|---|---|
| Allow CVE Scan → verdicts and proposals | ~35–60 s (longer the first time an advisory is analysed) |
| Verdicts → report email | ~1 min later (background) |
| Advisory judgment | ~1–2 min |
| Approve → applied (firewall / restart) | 1–3 s |
| Approve → applied (package upgrade) | 15–40 s |
| Applied → re-checked | ~25 s (only that server; works with scanning off) |

Use **Run Scan** on the Overview to trigger a scan immediately while scanning is allowed.

---

## 5. Between rehearsals

**Settings → Reset Environment.** It cancels anything still running (scan, report, judgment, re-check), clears findings, reports, approvals, judgments, chats and the event log, recreates the lab servers from their images (~30–45 s) and switches CVE scanning off. Then run `bun run healthcheck`.

If the health check reports a wrong PHP build, or bank-web-01 isn't vulnerable at the start, rebuild the lab assets:

```bash
bun run targets:reset
```

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Sidebar shows **Sentinel offline** | The brain stopped — restart `bun run brain`. |
| Assets show **Offline** / **cannot be assessed** | `bun run targets:up` (or bring the daemon back with the outage switch in Settings); daemons reconnect within ~30 s of the brain starting. Sentinel proposes nothing for such a server until it reports again. |
| Nothing happens after **Allow CVE Scan** | Check internet access (`bun run healthcheck`); click **Run Scan**. |
| An action stays on **Re-assessing** | The re-check waits up to 12 s for the server's inventory, then runs (~25 s). If the brain was restarted meanwhile, it re-checks pending actions on startup. |
| A judgment **failed** to fetch the advisory | Only public `https` URLs are allowed; some sites block automated readers — try the advisory on another site (e.g. GitHub Security Advisories). |
| Advisory Judge says the product is **not installed anywhere** | The lab images are older than the nginxWebUI stub: `bun run targets:up` rebuilds them. |
| Chat errors or stalls | LLM endpoint unreachable or key invalid — check `OPENCODE_API_KEY`, run the health check. |
| bank-web-01 not **Exposed** at the start | A remediation from a rehearsal is still applied: **Reset Environment**, or `bun run targets:reset`. |
| Lab servers can't reach the Ubuntu archive (upgrades fail) | The targets use pinned DNS (`1.1.1.1`, `8.8.8.8` in `docker-compose.yml`); check the host's internet access. |
| Dashboard keeps reloading | You are on the dev server — use `bun run web:prod`. |
| Port 4400 or 3000 in use | Change `BRAIN_PORT` / `BRAIN_URL` in `.env`, and for the lab assets set `PROHORI_BRAIN_URL=ws://host.docker.internal:<port>/agent` before `bun run targets:up`. |

---

## 7. Likely judge questions

- **"Is this tuned to PHP2Shell?"** — No. Sentinel's prompts and scan code contain no CVE ids, products or CVE-specific mitigations (`bun run prompt-audit` enforces it). The same pipeline handles regreSSHion in OpenSSH, Cyrus SASL and nginxWebUI with no changes. `bun run eval` scores the scan scenarios.
- **"What about brand-new or zero-day advisories?"** — That is the Advisory Judge: an admin hands Sentinel the advisory and gets a per-server verdict before any feed lists it. When no distribution record exists yet, Sentinel says the build check rests on the advisory's version numbers and flags it for confirmation.
- **"Is the nginxWebUI server real?"** — It is a lab stub: a real Debian package, process and listener for Sentinel to find, serving only a login page and refusing the vulnerable endpoint. We don't run exploitable code in the lab; Sentinel's judgment would be the same against the real application.
- **"How is this different from Tenable or Qualys?"** — Those tools list version matches and leave triage to an analyst. Sentinel decides which matches are actually exploitable on *this* asset (distro build, network reachability, exploitation status), writes the report, and drives an approved fix. It is built for organizations that cannot staff a security team.
- **"Can the AI break production?"** — Sentinel cannot approve anything (or track a judgment). The daemon only runs a short allow-list of reversible actions with validated parameters, and every change has a rollback. A server whose inventory can't be trusted gets no proposals at all.
- **"What if the model is wrong?"** — Statuses are decided by deterministic rules after the model; the model explains. When evidence is uncertain the more severe status is chosen and flagged for confirmation.
- **"Isn't Prohori itself a target?"** — Daemons connect outbound only, the brain holds no SSH keys, the daemon enforces its own allow-list, advisory URLs can only reach public https hosts, and every action is human-approved and audited.
