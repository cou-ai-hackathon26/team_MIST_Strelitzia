// Tier-2 actions. Only the allowlisted templates below can run; params are re-validated locally
// with ActionParams. Every command is an argv array (no shell). Rollback state lives on disk.
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ActionParams, CONFIG_DIRECTIVE_ALLOWLIST, type ActionType } from "@prohori/shared";
import { editIni, editSshd, globMatch, lexicallySafe, resolveAllowedPath, revertEdit } from "./configfile";
import { fmt, priv, run, truncate } from "./exec";
import { MULTIPART_SNIPPET, iniValue } from "./collect";
import { log } from "./log";
import { closeSpec, deleteRule, describe, insertRule, listRules } from "./firewall";

export interface ActionOutcome {
  ok: boolean;
  diff: string;
  output: string;
}

interface StateBase {
  actionId: string;
  type: ActionType;
  params: unknown;
  appliedAt: string;
  rolledBackAt?: string;
}
type ActionState =
  | (StateBase & { type: "firewall_port"; added: string[][]; removed: string[][] })
  | (StateBase & { type: "upgrade_packages"; changed: { pkg: string; from: string; to: string }[] })
  | (StateBase & { type: "nginx_block_multipart"; existedBefore: boolean })
  | (StateBase & { type: "set_php_directive"; file: string; oldLine: string | null; newLine: string; sapi: string })
  | (StateBase & { type: "set_config_directive"; file: string; format: "sshd" | "ini"; directive: string; oldLine: string | null; newLine: string; service: string })
  | (StateBase & { type: "restart_service" });

const BLOCK_MULTIPART_CONF = `# Managed by Prohori (nginx_block_multipart). Partial, interim PHP2Shell mitigation.
if ($content_type ~* "multipart/form-data") { return 415; }
`;

export class ActionRunner {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly tier2: boolean,
    private readonly stateDir: string,
  ) {}

  private get actionsDir() {
    return join(this.stateDir, "actions");
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn, fn);
    this.queue = p.catch(() => undefined);
    return p;
  }

  private statePath(actionId: string) {
    if (!/^[A-Za-z0-9_.-]{1,128}$/.test(actionId)) throw new Error("invalid actionId");
    return join(this.actionsDir, `${actionId}.json`);
  }

  private saveState(s: ActionState) {
    mkdirSync(this.actionsDir, { recursive: true });
    writeFileSync(this.statePath(s.actionId), JSON.stringify(s, null, 2));
  }

  /**
   * iptables rules are not persistent (container restart / VM reboot drops them). On startup, re-insert
   * rules from firewall_port actions that were applied and not rolled back, so a "closed" port stays closed.
   */
  reconcileFirewall(): Promise<void> {
    return this.serial(async () => {
      if (!this.tier2 || !existsSync(this.actionsDir)) return;
      const states = readdirSync(this.actionsDir)
        .filter((f) => f.endsWith(".json"))
        .map((f) => {
          try {
            return JSON.parse(readFileSync(join(this.actionsDir, f), "utf8")) as ActionState;
          } catch {
            return null;
          }
        })
        .filter((s): s is Extract<ActionState, { type: "firewall_port" }> => !!s && s.type === "firewall_port" && !s.rolledBackAt && s.added.length > 0);
      if (!states.length) return;
      const current = await listRules();
      if (!current.available) return;
      for (const s of states.sort((a, b) => a.appliedAt.localeCompare(b.appliedAt))) {
        for (const spec of s.added) {
          const comment = spec[spec.indexOf("--comment") + 1];
          if (current.rules.some((r) => r.comment === comment)) continue;
          const r = await insertRule(spec);
          log(`firewall reconcile: re-applied rule from ${s.actionId} ok=${r.ok}`);
        }
      }
    });
  }

  apply(actionId: string, actionType: string, rawParams: unknown): Promise<ActionOutcome> {
    return this.serial(async () => {
      if (!this.tier2) return { ok: false, diff: "", output: "tier2 disabled on this host" };
      if (!(actionType in ActionParams)) return { ok: false, diff: "", output: `unknown action type: ${actionType}` };
      const type = actionType as ActionType;
      const parsed = ActionParams[type].safeParse(rawParams);
      if (!parsed.success) return { ok: false, diff: "", output: `invalid params: ${parsed.error.message}` };
      try {
        this.statePath(actionId);
      } catch (e) {
        return { ok: false, diff: "", output: (e as Error).message };
      }
      if (existsSync(this.statePath(actionId))) return { ok: false, diff: "", output: `action ${actionId} was already applied on this host` };
      log(`action ${actionId}: apply ${type} ${JSON.stringify(parsed.data)}`);
      try {
        const r = await this.applyTyped(actionId, type, parsed.data as never);
        return { ...r, output: truncate(r.output) };
      } catch (e) {
        return { ok: false, diff: "", output: `error: ${(e as Error).message}` };
      }
    });
  }

  rollback(actionId: string): Promise<ActionOutcome> {
    return this.serial(async () => {
      if (!this.tier2) return { ok: false, diff: "", output: "tier2 disabled on this host" };
      let path: string;
      try {
        path = this.statePath(actionId);
      } catch (e) {
        return { ok: false, diff: "", output: (e as Error).message };
      }
      if (!existsSync(path)) return { ok: false, diff: "", output: `no rollback state for action ${actionId} on this host` };
      const state = JSON.parse(readFileSync(path, "utf8")) as ActionState;
      if (state.rolledBackAt) return { ok: false, diff: "", output: `action ${actionId} already rolled back at ${state.rolledBackAt}` };
      log(`action ${actionId}: rollback ${state.type}`);
      try {
        const r = await this.rollbackTyped(state);
        if (r.ok) {
          state.rolledBackAt = new Date().toISOString();
          writeFileSync(path, JSON.stringify(state, null, 2));
        }
        return { ...r, output: truncate(r.output) };
      } catch (e) {
        return { ok: false, diff: "", output: `error: ${(e as Error).message}` };
      }
    });
  }

  private async applyTyped(actionId: string, type: ActionType, params: any): Promise<ActionOutcome> {
    const base = { actionId, params, appliedAt: new Date().toISOString() };
    switch (type) {
      case "firewall_port": {
        const r = await firewallPort(actionId, params.port, params.protocol, params.state);
        if (r.ok && (r.added.length || r.removed.length)) this.saveState({ ...base, type, added: r.added, removed: r.removed });
        return r;
      }
      case "upgrade_packages": {
        const r = await upgradePackages(params.packages);
        if (r.changed.length) this.saveState({ ...base, type, changed: r.changed });
        return r;
      }
      case "nginx_block_multipart": {
        const r = await nginxBlockMultipart();
        if (r.ok && r.existedBefore === false) this.saveState({ ...base, type, existedBefore: false });
        return r;
      }
      case "set_php_directive": {
        const r = await setPhpDirective(params.sapi, params.directive, params.value);
        if (r.ok && r.file) this.saveState({ ...base, type, file: r.file, oldLine: r.oldLine, newLine: r.newLine!, sapi: params.sapi });
        return r;
      }
      case "set_config_directive": {
        const r = await setConfigDirective(params.file, params.directive, params.value);
        if (r.ok && r.state) this.saveState({ ...base, type, ...r.state });
        return r;
      }
      case "restart_service": {
        const r = await restartService(params.service);
        this.saveState({ ...base, type });
        return r;
      }
    }
  }

  private async rollbackTyped(s: ActionState): Promise<ActionOutcome> {
    switch (s.type) {
      case "firewall_port":
        return rollbackFirewall(s.added, s.removed);
      case "upgrade_packages":
        return rollbackUpgrade(s.changed);
      case "nginx_block_multipart":
        return rollbackBlockMultipart();
      case "set_php_directive":
        return rollbackPhpDirective(s.file, s.oldLine, s.newLine, s.sapi);
      case "set_config_directive":
        return rollbackConfigDirective(s);
      case "restart_service":
        return { ok: true, diff: "nothing to roll back (service restart)", output: "" };
    }
  }
}

// ---------------- helpers ----------------

async function dpkgVersions(): Promise<Map<string, string>> {
  const r = await run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Status}\n"], { timeoutMs: 30_000 });
  const m = new Map<string, string>();
  for (const line of r.stdout.split("\n")) {
    const [pkg, ver, status] = line.split("\t");
    if (pkg && ver && status === "installed") m.set(pkg, ver);
  }
  return m;
}

function serviceExists(name: string): boolean {
  return (
    existsSync(`/etc/init.d/${name}`) ||
    existsSync(`/lib/systemd/system/${name}.service`) ||
    existsSync(`/usr/lib/systemd/system/${name}.service`) ||
    existsSync(`/etc/systemd/system/${name}.service`)
  );
}

/** `service <name> <verb>`; falls back to systemctl when `service` is missing. */
async function serviceCmd(name: string, verb: "restart" | "reload"): Promise<{ ok: boolean; out: string }> {
  const hasService = existsSync("/usr/sbin/service") || existsSync("/sbin/service") || existsSync("/usr/bin/service");
  const argv = hasService ? ["service", name, verb] : ["systemctl", verb, name];
  const r = await run(priv(argv), { timeoutMs: 60_000 });
  return { ok: r.code === 0, out: fmt(argv, r) };
}

const APT_ENV = { DEBIAN_FRONTEND: "noninteractive" };

async function aptUpdateIfStale(): Promise<string> {
  const dir = "/var/lib/apt/lists";
  let newest = 0;
  if (existsSync(dir)) {
    for (const f of readdirSync(dir)) {
      if (!f.endsWith("InRelease") && !f.endsWith("_Release")) continue;
      newest = Math.max(newest, statSync(join(dir, f)).mtimeMs);
    }
  }
  const ageMin = (Date.now() - newest) / 60_000;
  if (newest > 0 && ageMin < 60) return `(apt lists are ${ageMin.toFixed(0)} min old; skipping apt-get update)\n`;
  const argv = ["apt-get", "update"];
  const r = await run(priv(argv), { timeoutMs: 180_000, env: APT_ENV });
  return fmt(argv, r);
}

function diffVersions(before: Map<string, string>, after: Map<string, string>) {
  const changed: { pkg: string; from: string; to: string }[] = [];
  for (const [pkg, to] of after) {
    const from = before.get(pkg);
    if (from !== undefined && from !== to) changed.push({ pkg, from, to });
  }
  return changed.sort((a, b) => a.pkg.localeCompare(b.pkg));
}

async function restartPhpFpmIfChanged(pkgs: string[]): Promise<string> {
  if (!pkgs.some((p) => p.startsWith("php8.3-"))) return "";
  if (!serviceExists("php8.3-fpm")) return "(php8.3-fpm service not present; no restart needed)\n";
  const r = await serviceCmd("php8.3-fpm", "restart");
  return r.out;
}

async function upgradePackages(packages: string[]) {
  let output = "";
  const before = await dpkgVersions();
  const notInstalled = packages.filter((p) => !before.has(p));
  const targets = packages.filter((p) => before.has(p));
  if (notInstalled.length) output += `(not installed, skipped: ${notInstalled.join(", ")})\n`;
  if (!targets.length) return { ok: false, diff: "", output: output + "none of the requested packages are installed", changed: [] };

  output += await aptUpdateIfStale();
  const argv = ["apt-get", "install", "-y", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold", ...targets];
  const r = await run(priv(argv), { timeoutMs: 600_000, env: APT_ENV });
  output += fmt(argv, r);

  const after = await dpkgVersions();
  const changed = diffVersions(before, after);
  output += await restartPhpFpmIfChanged(changed.map((c) => c.pkg));

  const lines = changed.map((c) => `${c.pkg}: ${c.from} → ${c.to}`);
  for (const p of targets) if (!changed.some((c) => c.pkg === p)) lines.push(`${p}: ${before.get(p)} (unchanged, already latest)`);
  return { ok: r.code === 0, diff: lines.join("\n"), output, changed };
}

async function rollbackUpgrade(changed: { pkg: string; from: string; to: string }[]): Promise<ActionOutcome> {
  let output = "";
  const before = await dpkgVersions();
  const argv = [
    "apt-get", "install", "-y", "--allow-downgrades", "-o", "Dpkg::Options::=--force-confold",
    ...changed.map((c) => `${c.pkg}=${c.from}`),
  ];
  let r = await run(priv(argv), { timeoutMs: 600_000, env: APT_ENV });
  output += fmt(argv, r);
  if (r.code !== 0 && /Unable to locate|not found|Version .* was not found/i.test(r.stderr)) {
    output += await aptUpdateIfStale();
    r = await run(priv(argv), { timeoutMs: 600_000, env: APT_ENV });
    output += fmt(argv, r);
  }
  const after = await dpkgVersions();
  const reverted = diffVersions(before, after);
  output += await restartPhpFpmIfChanged(reverted.map((c) => c.pkg));
  const lines = changed.map((c) => `${c.pkg}: ${before.get(c.pkg) ?? c.to} → ${after.get(c.pkg) ?? "(missing)"}`);
  const allBack = changed.every((c) => after.get(c.pkg) === c.from);
  return { ok: r.code === 0 && allBack, diff: lines.join("\n"), output };
}

async function nginxTest(): Promise<{ ok: boolean; out: string }> {
  const argv = ["nginx", "-t"];
  const r = await run(priv(argv), { timeoutMs: 30_000 });
  return { ok: r.code === 0, out: fmt(argv, r) };
}

async function nginxIncludesSnippet(): Promise<boolean> {
  const r = await run(priv(["nginx", "-T"]), { timeoutMs: 30_000 });
  return r.stdout.includes(`# configuration file ${MULTIPART_SNIPPET}:`);
}

async function nginxBlockMultipart(): Promise<ActionOutcome & { existedBefore?: boolean }> {
  if (!existsSync("/etc/nginx")) return { ok: false, diff: "", output: "nginx is not installed on this host" };
  if (existsSync(MULTIPART_SNIPPET)) return { ok: true, diff: "unchanged: multipart block already active", output: "", existedBefore: true };
  let output = "";
  mkdirSync(dirname(MULTIPART_SNIPPET), { recursive: true });
  writeFileSync(MULTIPART_SNIPPET, BLOCK_MULTIPART_CONF);
  const t = await nginxTest();
  output += t.out;
  if (!t.ok || !(await nginxIncludesSnippet())) {
    unlinkSync(MULTIPART_SNIPPET);
    const why = t.ok ? "snippet is not included by any server block (missing `include /etc/nginx/prohori/*.conf;`)" : "nginx -t failed";
    return { ok: false, diff: "", output: output + `reverted: ${why}\n` };
  }
  const rl = await serviceCmd("nginx", "reload");
  output += rl.out;
  return {
    ok: rl.ok,
    diff: `+ ${MULTIPART_SNIPPET}\n+   if ($content_type ~* "multipart/form-data") { return 415; }\nnginx:multipart_blocked: false → true`,
    output,
    existedBefore: false,
  };
}

async function rollbackBlockMultipart(): Promise<ActionOutcome> {
  let output = "";
  if (existsSync(MULTIPART_SNIPPET)) unlinkSync(MULTIPART_SNIPPET);
  const t = await nginxTest();
  output += t.out;
  const rl = await serviceCmd("nginx", "reload");
  output += rl.out;
  return { ok: t.ok && rl.ok, diff: `- ${MULTIPART_SNIPPET}\nnginx:multipart_blocked: true → false`, output };
}

const SAPI_SERVICE: Record<string, string | null> = { fpm: "php8.3-fpm", cli: null, apache2: "apache2" };

async function setPhpDirective(sapi: string, directive: string, value: string) {
  const file = `/etc/php/8.3/${sapi}/php.ini`;
  if (!existsSync(file)) return { ok: false, diff: "", output: `${file} does not exist (SAPI not installed)`, file: null, oldLine: null, newLine: null };
  const lines = readFileSync(file, "utf8").split("\n");
  const active = new RegExp(`^\\s*${directive}\\s*=`);
  const commented = new RegExp(`^\\s*;\\s*${directive}\\s*=`);
  const newLine = `${directive} = ${value}`;
  let idx = -1;
  lines.forEach((l, i) => active.test(l) && (idx = i));
  let oldLine: string | null = null;
  if (idx >= 0) {
    oldLine = lines[idx]!;
    lines[idx] = newLine;
  } else {
    let cidx = -1;
    lines.forEach((l, i) => commented.test(l) && (cidx = i));
    if (cidx >= 0) lines.splice(cidx + 1, 0, newLine);
    else lines.push(newLine);
  }
  writeFileSync(file, lines.join("\n"));
  let output = `edited ${file}\n`;
  const svc = SAPI_SERVICE[sapi];
  let ok = true;
  if (svc && serviceExists(svc)) {
    const r = await serviceCmd(svc, "restart");
    output += r.out;
    ok = r.ok;
  } else if (!svc) output += "(cli SAPI: no service to restart; takes effect for new php processes)\n";
  const effective = iniValue(readFileSync(file, "utf8"), directive);
  ok = ok && effective === value;
  return { ok, diff: `${file}:${directive}: ${oldLine ? (iniValue(oldLine, directive) ?? "?") : "(unset)"} → ${effective}`, output, file, oldLine, newLine };
}

async function rollbackPhpDirective(file: string, oldLine: string | null, newLine: string, sapi: string): Promise<ActionOutcome> {
  const lines = readFileSync(file, "utf8").split("\n");
  const idx = lines.lastIndexOf(newLine);
  if (idx < 0) return { ok: false, diff: "", output: `line "${newLine}" not found in ${file}; was it changed by someone else?` };
  if (oldLine === null) lines.splice(idx, 1);
  else lines[idx] = oldLine;
  writeFileSync(file, lines.join("\n"));
  let output = `restored ${file}\n`;
  let ok = true;
  const svc = SAPI_SERVICE[sapi];
  if (svc && serviceExists(svc)) {
    const r = await serviceCmd(svc, "restart");
    output += r.out;
    ok = r.ok;
  }
  const directive = newLine.split("=")[0]!.trim();
  return { ok, diff: `${file}:${directive}: ${iniValue(newLine, directive)} → ${oldLine ? iniValue(oldLine, directive) : "(unset)"}`, output };
}

async function restartService(service: string): Promise<ActionOutcome> {
  if (!serviceExists(service)) return { ok: false, diff: "", output: `service ${service} is not installed` };
  const r = await serviceCmd(service, "restart");
  return { ok: r.ok, diff: r.ok ? `${service}: restarted` : `${service}: restart failed`, output: service === "ssh" ? sanitizeSshdOutput(r.out, "/etc/ssh/sshd_config") : r.out };
}

// ---------------- set_config_directive ----------------

type ConfigState = { file: string; format: "sshd" | "ini"; directive: string; oldLine: string | null; newLine: string; service: string };

const SSH_TIME = /^(\d+[smhdwSMHDW]?)+$/;
/** sshd -T prints normalized values (times in seconds, lowercase keywords); normalize ours the same way. */
function normSshd(v: string): string {
  const x = v.trim().toLowerCase();
  if (SSH_TIME.test(x)) {
    const mult: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 };
    let total = 0;
    for (const [, n, u] of x.matchAll(/(\d+)([smhdw]?)/g)) total += Number(n) * (mult[u || "s"] ?? 1);
    return String(total);
  }
  if (x === "prohibit-password") return "without-password";
  return x;
}

/**
 * sshd error messages echo the offending line of whatever file it parsed (e.g. a file planted via Include).
 * Before output leaves the host: keep messages about the edited file, count (don't echo) the rest, redact quotes.
 */
function sanitizeSshdOutput(text: string, file: string): string {
  const kept: string[] = [];
  const omitted = new Map<string, number>();
  for (const line of text.split("\n")) {
    const m = /^(\/\S+?):?(?: line \d+)?:/.exec(line);
    if (m && m[1] !== file && !line.startsWith("$ ")) {
      omitted.set(m[1]!, (omitted.get(m[1]!) ?? 0) + 1);
      continue;
    }
    kept.push(line.replace(/"[^"]*"/g, '"…"'));
  }
  for (const [f, n] of omitted) kept.splice(1, 0, `(${n} message(s) about ${f} omitted)`);
  return kept.slice(0, 40).join("\n") + (kept.length > 40 ? "\n…" : "");
}

async function sshdTest(file = "/etc/ssh/sshd_config"): Promise<{ ok: boolean; out: string }> {
  const argv = ["sshd", "-t"];
  const r = await run(priv(argv), { timeoutMs: 20_000 });
  return { ok: r.code === 0, out: sanitizeSshdOutput(fmt(argv, r), file) };
}

/** Effective (global, non-Match) value of an sshd keyword per `sshd -T`. */
async function sshdEffective(directive: string): Promise<{ value: string | null; out: string }> {
  const argv = ["sshd", "-T"];
  const r = await run(priv(argv), { timeoutMs: 20_000 });
  if (r.code !== 0) return { value: null, out: fmt(argv, r) };
  const key = directive.toLowerCase();
  const line = r.stdout.split("\n").find((l) => l.toLowerCase().startsWith(`${key} `));
  return { value: line ? line.slice(key.length + 1).trim() : null, out: `$ ${argv.join(" ")} | grep -i ^${key}\n${line ?? "(not reported)"}\n` };
}

function fpmBinary(file: string): string | null {
  const m = /^\/etc\/php\/([0-9.]+)\/fpm\/php\.ini$/.exec(file);
  return m ? `php-fpm${m[1]}` : null;
}

/** Syntax check for the edited file (sshd -t / php-fpm -t). */
async function validateConfig(file: string, format: "sshd" | "ini"): Promise<{ ok: boolean; out: string }> {
  if (format === "sshd") return sshdTest(file);
  const fpm = fpmBinary(file);
  if (!fpm) return { ok: true, out: "(no syntax checker for this file)\n" };
  const argv = [fpm, "-t"];
  const r = await run(priv(argv), { timeoutMs: 20_000 });
  return { ok: r.code === 0, out: fmt(argv, r) };
}

async function restartAndCheck(service: string): Promise<{ ok: boolean; out: string }> {
  if (!service) return { ok: true, out: "(no service to restart; takes effect for new processes)\n" };
  if (!serviceExists(service)) return { ok: true, out: `(service ${service} is not installed; nothing to restart)\n` };
  const r = await serviceCmd(service, "restart");
  if (!r.ok) return r;
  const st = await run(existsSync("/usr/sbin/service") ? ["service", service, "status"] : ["systemctl", "is-active", service], { timeoutMs: 15_000 });
  return { ok: st.code === 0, out: r.out + fmt(["service", service, "status"], st) };
}

async function setConfigDirective(file: string, directive: string, value: string): Promise<ActionOutcome & { state?: ConfigState }> {
  // Re-validate against the daemon-side allow-list (params were already zod-validated).
  const lex = lexicallySafe(file);
  if (lex) return { ok: false, diff: "", output: `rejected file: ${lex}` };
  const entries = CONFIG_DIRECTIVE_ALLOWLIST.filter((e) => globMatch(e.file, file));
  if (!entries.length) return { ok: false, diff: "", output: `rejected: ${file} is not in the config directive allow-list` };
  let entry: (typeof entries)[number] | undefined;
  let canonical: string | undefined;
  for (const e of entries) {
    canonical = e.directives.find((d) => d.toLowerCase() === directive.toLowerCase());
    if (canonical) {
      entry = e;
      break;
    }
  }
  if (!entry || !canonical) {
    return { ok: false, diff: "", output: `rejected: directive ${directive} is not allow-listed for ${file} (allowed: ${entries.flatMap((e) => e.directives).join(", ")})` };
  }
  if (!/^[A-Za-z0-9 :._\/-]{1,40}$/.test(value)) return { ok: false, diff: "", output: "rejected: invalid value" };
  const format: "sshd" | "ini" | null = file.startsWith("/etc/ssh/") ? "sshd" : file.endsWith("/php.ini") ? "ini" : null;
  if (!format) return { ok: false, diff: "", output: `rejected: no editor for ${file}` };
  let real: string;
  try {
    real = resolveAllowedPath(file, [entry.file]);
  } catch (e) {
    return { ok: false, diff: "", output: (e as Error).message };
  }

  const before = readFileSync(real, "utf8");
  const edit = format === "sshd" ? editSshd(before, canonical, value) : editIni(before, canonical, value);
  let output = `edited ${file}${real !== file ? ` (-> ${real})` : ""}: ${edit.oldLine === null ? "inserted" : `replaced "${edit.oldLine.trim()}" with`} "${edit.newLine}"\n`;
  writeFileSync(real, edit.text);

  let restarted = false;
  const restore = async (why: string): Promise<ActionOutcome> => {
    writeFileSync(real, before);
    output += `reverted ${file}: ${why}\n`;
    if (restarted && entry!.service && serviceExists(entry!.service)) {
      const r = await serviceCmd(entry!.service, "restart");
      output += format === "sshd" ? sanitizeSshdOutput(r.out, real) : r.out;
    }
    return { ok: false, diff: "", output };
  };

  const v = await validateConfig(real, format);
  output += v.out;
  if (!v.ok) return restore("config validation failed");
  // Verify the new value is the effective one (sshd -T parses the config the way sshd will) before restarting.
  let effective: string | null;
  if (format === "sshd") {
    const eff = await sshdEffective(canonical);
    output += eff.out;
    effective = eff.value;
    if (effective === null || normSshd(effective) !== normSshd(value)) {
      return restore(`effective ${canonical} would be ${effective ?? "unknown"}, not ${value} (set earlier, e.g. by an Include?)`);
    }
  } else {
    effective = iniValue(readFileSync(real, "utf8"), canonical);
    if (effective !== value) return restore(`effective ${canonical} would be ${effective ?? "unset"}, not ${value}`);
  }

  restarted = true;
  const rs = await restartAndCheck(entry.service);
  output += format === "sshd" ? sanitizeSshdOutput(rs.out, real) : rs.out;
  if (!rs.ok) return restore(`restart of ${entry.service} failed`);

  const minus = edit.oldLine === null ? `- (absent; default applies)` : `- ${edit.oldLine}`;
  return {
    ok: true,
    diff: `--- ${file}\n+++ ${file}\n${minus}\n+ ${edit.newLine}\n${file}:${canonical}: ${edit.previousValue ?? "(unset)"} → ${effective}`,
    output,
    state: { file: real, format, directive: canonical, oldLine: edit.oldLine, newLine: edit.newLine, service: entry.service },
  };
}

async function rollbackConfigDirective(s: ConfigState): Promise<ActionOutcome> {
  const current = readFileSync(s.file, "utf8");
  const reverted = revertEdit(current, s.format, s.newLine, s.oldLine);
  if (reverted === null) return { ok: false, diff: "", output: `line "${s.newLine}" not found in ${s.file}; was it changed by someone else?` };
  writeFileSync(s.file, reverted);
  let output = `restored ${s.file}\n`;
  const v = await validateConfig(s.file, s.format);
  output += v.out;
  if (!v.ok) {
    writeFileSync(s.file, current);
    return { ok: false, diff: "", output: output + "restored file failed validation; kept the current version\n" };
  }
  const rs = await restartAndCheck(s.service);
  output += s.format === "sshd" ? sanitizeSshdOutput(rs.out, s.file) : rs.out;
  let after = s.format === "ini" ? iniValue(reverted, s.directive) : null;
  if (s.format === "sshd") {
    const eff = await sshdEffective(s.directive);
    output += eff.out;
    after = eff.value;
  }
  const plus = s.oldLine === null ? "+ (absent; default applies)" : `+ ${s.oldLine}`;
  return { ok: rs.ok, diff: `--- ${s.file}\n+++ ${s.file}\n- ${s.newLine}\n${plus}\n${s.file}:${s.directive}: now ${after ?? "(unset)"}`, output };
}

// ---------------- firewall_port ----------------

async function firewallPort(actionId: string, port: number, protocol: "tcp" | "udp", state: "closed" | "open") {
  const none = { added: [] as string[][], removed: [] as string[][] };
  if (port === 22) return { ok: false, diff: "", output: "port 22 (SSH) is never managed by Prohori", ...none };
  const before = await listRules();
  if (!before.available) return { ok: false, diff: "", output: `iptables not usable on this host: ${before.error ?? ""}`, ...none };
  const matching = before.rules.filter((r) => r.port === port && r.protocol === protocol);
  let output = "";
  const added: string[][] = [];
  const removed: string[][] = [];
  let ok = true;
  if (state === "closed") {
    if (matching.length) {
      return { ok: true, diff: `unchanged: ${port}/${protocol} already closed by a prohori rule\nprohori rules:\n${describe(before.rules)}`, output, ...none };
    }
    const spec = closeSpec(port, protocol, actionId);
    const r = await insertRule(spec);
    output += r.out;
    ok = r.ok;
    if (r.ok) added.push(spec);
  } else {
    if (!matching.length) {
      return { ok: true, diff: `unchanged: ${port}/${protocol} is not closed by any prohori rule\nprohori rules:\n${describe(before.rules)}`, output, ...none };
    }
    for (const rule of matching) {
      const r = await deleteRule(rule.spec);
      output += r.out;
      ok &&= r.ok;
      if (r.ok) removed.push(rule.spec);
    }
  }
  const after = await listRules();
  const nowClosed = after.rules.some((r) => r.port === port && r.protocol === protocol);
  ok = ok && nowClosed === (state === "closed");
  return { ok, diff: `prohori rules before:\n${describe(before.rules)}\nprohori rules after:\n${describe(after.rules)}`, output, added, removed };
}

async function rollbackFirewall(added: string[][], removed: string[][]): Promise<ActionOutcome> {
  const before = await listRules();
  let output = "";
  let ok = true;
  const present = (spec: string[]) => before.rules.some((r) => r.spec.join(" ") === spec.join(" ") || r.comment === spec[spec.indexOf("--comment") + 1]);
  for (const spec of added) {
    if (!present(spec)) {
      output += "(rule already gone)\n";
      continue;
    }
    // delete by our exact rule (comment carries the action id)
    const rule = before.rules.find((r) => r.comment === spec[spec.indexOf("--comment") + 1]);
    const r = await deleteRule(rule ? rule.spec : spec);
    output += r.out;
    ok &&= r.ok;
  }
  for (const spec of removed) {
    if (present(spec)) continue;
    const r = await insertRule(spec);
    output += r.out;
    ok &&= r.ok;
  }
  const after = await listRules();
  return { ok, diff: `prohori rules before:\n${describe(before.rules)}\nprohori rules after:\n${describe(after.rules)}`, output };
}
