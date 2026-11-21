# Prohori — Demo Runbook

A step-by-step guide for presenting Prohori live. Target length: **about 3 minutes**, plus Q&A.

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

Then in the browser:

1. Open **http://localhost:3000**, sign in as `nusrat` / `prohori-admin`.
2. **Settings → Demonstration Controls**: PHP2Shell (and regreSSHion) must show **Embargoed**. If not, click **Reset Environment** and wait ~1 minute.
3. **Warm Sentinel's cache (recommended):** replay PHP2Shell once, wait for the verdicts, then **Reset Environment**. The advisory analysis is cached, so the on-stage detection is faster (~60 s instead of ~2 min).
4. **Overview**: four assets **Online**, no critical banner, *Recent Detections* empty.
5. Open **http://localhost:8025** (Mailpit) in a second tab and clear old messages.
6. Optional: in **Settings**, lower the scan interval to **20 s** so discovery is quicker on stage.
7. Keep a second tab with **Approvals** open, and have the chat prompts below ready to paste.

**Network:** Sentinel needs internet access for OSV.dev, CISA KEV and the LLM. Have a phone hotspot ready. Record one clean run as a backup video.

---

## 2. The script

### Scene 1 — The problem (30 s)

*Overview page.*

> "In October, PHP2Shell forced Bangladesh Bank and six banks offline for up to three days. Not because they were all hacked — because nobody could tell which servers were really vulnerable, so they shut everything down. These are three bank servers. Every one of them reports PHP 8.3.6, which is below the fixed upstream version. A version check would say all three are vulnerable."

Point at the three asset cards and the PHP build line on each.

### Scene 2 — Sentinel discovers it (45 s)

*Settings → Demonstration Controls → **Replay Disclosure** on PHP2Shell, then go back to Overview.*

> "We're replaying the real October 21st disclosure, with today's real data from OSV and CISA. Nobody touches Prohori from here — Sentinel picks it up on its own next scheduled scan."

Within one scan interval plus Sentinel's analysis (~60 s with a warm cache, ~2 min cold):

- The **Critical exposure detected on bank-web-01** banner appears.
- **Recent Detections** shows: bank-web-01 **Exposed**, bank-batch-01 **Vulnerable · Unreachable**, bank-web-02 **Not Affected**.

> "Same version number, three different realities. bank-web-02 runs Ubuntu's patched build — the fix was backported without changing the version. bank-batch-01 has the vulnerable build but only runs PHP from the command line; nothing reaches it from the network. Only bank-web-01 is an emergency."

**Show the work (30 s):** click **Investigate** on the banner. Scroll through *Sentinel's Investigation*: the threat profile it derived from the advisory (complete fix, partial mitigations and their trade-offs), the preconditions with citations, and the checks it ran on bank-web-01.

> "None of this is hard-coded. Sentinel read PHP's own advisory, worked out what makes this exploitable, checked those conditions on each server, and cited its evidence. Code guardrails sit on top: a patched build is always safe, and an uncited claim is never trusted."

### Scene 3 — The report (20 s)

*Switch to the Mailpit tab.*

> "The security team already has the incident report: what the CVE is, that it's being exploited in the wild, exactly which server is exposed and why, and the fix — upgrade is the complete fix, anything else is containment."

### Scene 4 — Ask Sentinel (30 s)

*Sentinel page, paste:*

`Why is bank-web-02 not affected by PHP2Shell?`

> "Sentinel answers from live data — you can see every tool call as it checks the inventory and the advisory."

### Scene 5 — Human-approved remediation (45 s)

*Approvals → on "Close port 80/tcp on bank-web-01" click **Review with Sentinel**, then paste:*

`We can't take the website down during business hours. What are our options?`

> "Sentinel proposed two things automatically: immediate containment and the real fix. The admin pushes back, Sentinel explains the trade-off — and if asked, revises the proposal. It can never approve anything itself."

Then click **Approve** on the pinned proposal, add a note (e.g. `Contain now, upgrade tonight`), **Confirm Approval**.

> "The daemon on the server applies exactly this change — nothing else is possible — and Sentinel re-assesses."

Watch for *Remediation applied — Sentinel is re-assessing…*; bank-web-01 moves from **Exposed** to **Vulnerable · Unreachable** (firewall) or **Not Affected** (upgrade).

### Scene 6 — Accountability (15 s)

*Audit Log.*

> "Every step is attributed: what Sentinel detected, the report that went out, and that nusrat approved the change, with her note and a link to the discussion."

**Closing line:**

> "From disclosure to the right team holding the fix — in minutes, not the 43-day industry average. And for organizations that can't afford a security team, Sentinel is that team."

---

## 3. Timing reference

| Step | Typical time |
|---|---|
| Replay → detection | next scan interval (45 s default, 20 s recommended) + ~60 s analysis (≈2 min if the CVE was never analysed before) |
| Approve → applied (firewall / restart) | 1–3 s |
| Approve → applied (package upgrade) | 15–40 s |
| Applied → re-assessed | ~10 s + scan time (15–35 s when the verdict changes) |

Use **Run Scan** on the Overview to trigger a scan immediately if you are short on time.

---

## 4. Between rehearsals

1. **Settings → Reset Environment.** This rolls back every remediation still applied on the lab assets, re-embargoes PHP2Shell and clears its findings, reports and proposals.
2. Wait ~1 minute (package downgrades take the longest), then run `bun run healthcheck`.

If the health check reports a wrong PHP build, or the dashboard shows **"Demo check: no asset is vulnerable…"**, rebuild the lab assets:

```bash
bun run targets:reset
```

---

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| Sidebar shows **Sentinel offline** | The brain stopped — restart `bun run brain`. |
| Assets show **Offline** | `bun run targets:up`; the daemons reconnect within ~30 s of the brain starting. |
| Nothing happens after Replay | Wait one full scan interval, or click **Run Scan**. Check internet access (`bun run healthcheck`). |
| Chat errors or stalls | LLM endpoint unreachable or key invalid — check `OPENCODE_API_KEY`, run the health check. |
| bank-web-01 not **Exposed** at the start | A remediation from a rehearsal is still applied: **Reset Environment**, or `bun run targets:reset`. |
| Dashboard keeps reloading | You are on the dev server — use `bun run web:prod`. |
| Port 4400 or 3000 in use | Change `BRAIN_PORT` / `BRAIN_URL` in `.env`, and for the lab assets set `PROHORI_BRAIN_URL=ws://host.docker.internal:<port>/agent` before `bun run targets:up`. |

---

## 6. Likely judge questions

- **"Is this tuned to PHP2Shell?"** — No. Sentinel's prompts and scan code contain no CVE ids, products or CVE-specific mitigations (`bun run prompt-audit` enforces it). A held-out scenario, regreSSHion in OpenSSH, is detected and planned with no changes — including working around the fact that Prohori never firewalls SSH port 22. `bun run eval` scores both scenarios.

- **"How is this different from Tenable or Qualys?"** — Those tools list version matches and leave triage to an analyst. Sentinel decides which matches are actually exploitable on *this* asset (distro build, network reachability, KEV status), writes the report, and drives an approved fix. It is built for organizations that cannot staff a security team.
- **"Can the AI break production?"** — Sentinel cannot approve anything. The daemon only runs a short allow-list of reversible actions with validated parameters, and every change has a rollback.
- **"What if the model is wrong?"** — Statuses are decided by deterministic rules after the model; the model explains. When evidence is uncertain the more severe status is chosen and flagged for confirmation.
- **"What about zero-days?"** — Out of scope. Prohori closes the window between a public disclosure and remediation, which is where most real-world exploitation happens.
- **"Isn't Prohori itself a target?"** — Daemons connect outbound only, the brain holds no SSH keys, the daemon enforces its own allow-list, and every action is human-approved and audited.
