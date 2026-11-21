// Allow-listed config files: read-only parsing for the `config_file` query, and the line edits used by the
// `set_config_directive` action. Paths are matched against CONFIG_PATHS (simple globs), symlinks are resolved
// and the resolved path is checked again. Nothing outside the allow-list is ever opened.
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { CONFIG_PATHS } from "@prohori/shared";

export const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_ROWS = 3000;
const MAX_INCLUDE_DEPTH = 3;

/**
 * Daemon-local additions that are accepted ONLY as the resolved target of an allow-listed symlink
 * (Debian layout: /etc/nginx/sites-enabled/x -> /etc/nginx/sites-available/x). They can't be requested directly.
 */
const RESOLVED_ONLY_PATHS = ["/etc/nginx/sites-available/*"];

export type ConfigRow = { key: string; value: string; file: string };
export type ConfigFormat = "sshd" | "ini" | "nginx" | "kv" | "apache";

/** Glob → RegExp. `*` and `?` never match `/`; everything else is literal. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (const ch of glob) {
    if (ch === "*") re += "[^/]*";
    else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function globMatch(glob: string, path: string): boolean {
  return globToRegExp(glob).test(path);
}

/** Lexical checks: absolute, no `.`/`..` segments, no empty segments, no NUL, no glob characters. */
export function lexicallySafe(path: string): string | null {
  if (typeof path !== "string" || !path) return "path is required";
  if (path.length > 256) return "path too long";
  if (!path.startsWith("/")) return "path must be absolute";
  if (/[\0*?\[\]]/.test(path)) return "path must be a concrete file path (no glob characters)";
  const segs = path.split("/").slice(1);
  if (segs.some((s) => s === "" || s === "." || s === "..")) return "path must not contain '.', '..' or empty segments";
  return null;
}

/**
 * Validate a requested config path: lexical checks, allow-list match, realpath re-check, regular file, size cap.
 * Returns the resolved path or throws with a reason.
 */
export function resolveAllowedPath(path: string, allow: readonly string[] = CONFIG_PATHS): string {
  const lex = lexicallySafe(path);
  if (lex) throw new Error(`rejected path: ${lex}`);
  if (!allow.some((g) => globMatch(g, path))) throw new Error(`rejected path: ${path} is not an allow-listed config file`);
  if (!existsSync(path)) throw new Error(`${path} does not exist on this host`);
  let real: string;
  try {
    real = realpathSync(path);
  } catch (e) {
    throw new Error(`cannot resolve ${path}: ${(e as Error).message}`);
  }
  if (real !== path && ![...allow, ...RESOLVED_ONLY_PATHS].some((g) => globMatch(g, real)))
    throw new Error(`rejected path: ${path} resolves to ${real}, which is not allow-listed`);
  const st = statSync(real);
  if (!st.isFile()) throw new Error(`rejected path: ${path} is not a regular file`);
  if (st.size > MAX_CONFIG_BYTES) throw new Error(`rejected path: ${path} is larger than ${MAX_CONFIG_BYTES} bytes`);
  return real;
}

export function formatFor(path: string): ConfigFormat {
  if (path.startsWith("/etc/ssh/")) return "sshd";
  if (path.endsWith("/php.ini")) return "ini";
  if (path.startsWith("/etc/nginx/")) return "nginx";
  if (path.startsWith("/etc/apache2/")) return "apache";
  return "kv"; // my.cnf, redis.conf
}

// ---------------- parsers ----------------

/** Strip a trailing comment introduced by any char in `marks` (outside double/single quotes). */
function stripComment(line: string, marks: string): string {
  let q: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (q) {
      if (c === "\\") i++;
      else if (c === q) q = null;
    } else if (c === '"' || c === "'") q = c;
    else if (marks.includes(c) && (i === 0 || /\s/.test(line[i - 1]!))) return line.slice(0, i);
  }
  return line;
}

const unquote = (v: string) => v.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");

/** sshd_config: `Keyword value` or `Keyword=value`; `Match` opens a conditional block until the next Match. */
function parseSshd(text: string, file: string, depth: number, out: ConfigRow[]) {
  let match: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(\S+?)(?:\s*=\s*|\s+)(.*)$/.exec(line) ?? /^(\S+)()$/.exec(line);
    if (!m) continue;
    const key = m[1]!;
    const value = unquote(stripComment(m[2]!, "#").trim()).replace(/\s+/g, " ");
    if (/^match$/i.test(key)) {
      match = /^all$/i.test(value) ? null : value;
      out.push({ key, value, file });
      continue;
    }
    out.push({ key: match ? `Match ${match} > ${key}` : key, value, file });
    if (/^include$/i.test(key) && !match) {
      for (const pattern of value.split(/\s+/).filter(Boolean)) expandInclude(pattern, file, depth, out);
    }
  }
}

/** sshd Include: relative paths are relative to /etc/ssh; only allow-listed files are followed. */
function expandInclude(pattern: string, from: string, depth: number, out: ConfigRow[]) {
  if (depth >= MAX_INCLUDE_DEPTH) {
    out.push({ key: "#include-skipped", value: `${pattern} (include depth limit)`, file: from });
    return;
  }
  const abs = pattern.startsWith("/") ? pattern : join("/etc/ssh", pattern);
  const dir = dirname(abs);
  const base = abs.slice(dir.length + 1);
  if (/[*?[]/.test(dir)) {
    out.push({ key: "#include-skipped", value: `${pattern} (wildcard directories not followed)`, file: from });
    return;
  }
  let candidates: string[] = [];
  if (/[*?]/.test(base)) {
    if (existsSync(dir)) {
      const re = globToRegExp(base);
      candidates = readdirSync(dir).filter((f) => re.test(f)).sort().map((f) => join(dir, f));
    }
  } else if (existsSync(abs)) candidates = [abs];
  for (const c of candidates) {
    let real: string;
    try {
      real = resolveAllowedPath(c);
    } catch (e) {
      out.push({ key: "#include-skipped", value: `${c} (${(e as Error).message})`, file: from });
      continue;
    }
    parseSshd(readFileSync(real, "utf8"), c, depth + 1, out);
  }
}

/** php.ini: `key = value`, `;` comments, sections ignored (php applies them globally). */
function parseIni(text: string, file: string, out: ConfigRow[]) {
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#") || line.startsWith("[")) continue;
    const m = /^([^=\s]+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    out.push({ key: m[1]!, value: unquote(stripComment(m[2]!, ";").trim()), file });
  }
}

/** my.cnf / redis.conf: `key value`, `key = value` or a bare flag; `[section]` prefixes keys. */
function parseKv(text: string, file: string, out: ConfigRow[]) {
  let section: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[([^\]]+)\]$/.exec(line);
    if (sec) {
      section = sec[1]!.trim();
      continue;
    }
    const m = /^([^=\s]+)(?:\s*=\s*|\s+)(.*)$/.exec(line) ?? /^(\S+)()$/.exec(line);
    if (!m) continue;
    out.push({ key: section ? `${section} > ${m[1]}` : m[1]!, value: unquote(stripComment(m[2]!, "#;").trim()), file });
  }
}

/** nginx: `directive args;` and `name args { ... }` blocks, flattened as "http > server > location / > directive". */
function parseNginx(text: string, file: string, out: ConfigRow[]) {
  const tokens: string[] = [];
  for (const raw of text.split("\n")) {
    const line = stripComment(raw, "#");
    const re = /"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|([{};])|([^\s{};"']+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) tokens.push(m[1] ?? m[2] ?? m[3] ?? m[4]!);
  }
  const stack: string[] = [];
  let words: string[] = [];
  for (const t of tokens) {
    if (t === ";") {
      if (words.length) out.push({ key: [...stack, words[0]!].join(" > "), value: words.slice(1).join(" "), file });
      words = [];
    } else if (t === "{") {
      stack.push(words.join(" "));
      words = [];
    } else if (t === "}") {
      stack.pop();
      words = [];
    } else words.push(t);
  }
}

/** apache2.conf: `Directive args`, `<Section args>` … `</Section>` blocks, `\` continuations. */
function parseApache(text: string, file: string, out: ConfigRow[]) {
  const stack: string[] = [];
  const lines = text.replace(/\\\n/g, " ").split("\n");
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const close = /^<\/\s*([^>]+)>$/.exec(line);
    if (close) {
      stack.pop();
      continue;
    }
    const open = /^<\s*([^>]+)>$/.exec(line);
    if (open) {
      stack.push(open[1]!.trim());
      continue;
    }
    const m = /^(\S+)\s*(.*)$/.exec(line);
    if (m) out.push({ key: [...stack, m[1]!].join(" > "), value: m[2]!.trim(), file });
  }
}

/** The `config_file` query. */
export function readConfigFile(path: string | undefined): ConfigRow[] {
  if (!path) throw new Error("config_file requires params.path");
  const real = resolveAllowedPath(path);
  const text = readFileSync(real, "utf8");
  const out: ConfigRow[] = [];
  switch (formatFor(path)) {
    case "sshd":
      parseSshd(text, path, 0, out);
      break;
    case "ini":
      parseIni(text, path, out);
      break;
    case "nginx":
      parseNginx(text, path, out);
      break;
    case "apache":
      parseApache(text, path, out);
      break;
    case "kv":
      parseKv(text, path, out);
      break;
  }
  return out.slice(0, MAX_ROWS);
}

// ---------------- editing (set_config_directive) ----------------

export interface DirectiveEdit {
  text: string;            // new file content
  oldLine: string | null;  // replaced line, or null when the directive was inserted
  newLine: string;
  previousValue: string | null;
}

/**
 * sshd_config: the FIRST occurrence of a keyword wins, and directives after a `Match` line are conditional.
 * Replace the first active occurrence before any Match block; otherwise insert after the commented default
 * (if that is before the first Match) or right before the first Match / at the end.
 */
export function editSshd(text: string, directive: string, value: string): DirectiveEdit {
  const lines = text.split("\n");
  const newLine = `${directive} ${value}`;
  const firstMatch = lines.findIndex((l) => /^\s*Match\s/i.test(l));
  const limit = firstMatch < 0 ? lines.length : firstMatch;
  const active = new RegExp(`^\\s*${directive}(\\s+|\\s*=\\s*)(.*)$`, "i");
  const commented = new RegExp(`^\\s*#\\s*${directive}(\\s|=)`, "i");
  for (let i = 0; i < limit; i++) {
    const m = active.exec(lines[i]!);
    if (m) {
      const oldLine = lines[i]!;
      lines[i] = newLine;
      return { text: lines.join("\n"), oldLine, newLine, previousValue: stripComment(m[2]!, "#").trim() };
    }
  }
  let at = -1;
  for (let i = 0; i < limit; i++) if (commented.test(lines[i]!)) at = i + 1;
  if (at < 0) {
    if (firstMatch >= 0) at = firstMatch;
    else {
      at = lines.length;
      if (lines[at - 1] === "") at--; // keep the trailing newline at the end
    }
  }
  lines.splice(at, 0, newLine);
  return { text: lines.join("\n"), oldLine: null, newLine, previousValue: null };
}

/** php.ini: the LAST active `key = value` wins. Replace it, or insert after the commented default / append. */
export function editIni(text: string, directive: string, value: string): DirectiveEdit {
  const lines = text.split("\n");
  const newLine = `${directive} = ${value}`;
  const esc = directive.replace(/\./g, "\\.");
  const active = new RegExp(`^\\s*${esc}\\s*=\\s*(.*)$`);
  const commented = new RegExp(`^\\s*;\\s*${esc}\\s*=`);
  let idx = -1;
  let prev: string | null = null;
  lines.forEach((l, i) => {
    const m = active.exec(l);
    if (m) {
      idx = i;
      prev = unquote(stripComment(m[1]!, ";").trim());
    }
  });
  if (idx >= 0) {
    const oldLine = lines[idx]!;
    lines[idx] = newLine;
    return { text: lines.join("\n"), oldLine, newLine, previousValue: prev };
  }
  let at = -1;
  lines.forEach((l, i) => commented.test(l) && (at = i + 1));
  if (at < 0) {
    at = lines.length;
    if (lines[at - 1] === "") at--;
  }
  lines.splice(at, 0, newLine);
  return { text: lines.join("\n"), oldLine: null, newLine, previousValue: null };
}

/** Undo an edit: find our line (first for sshd, last for ini) and restore the old line or drop the inserted one. */
export function revertEdit(text: string, format: "sshd" | "ini", newLine: string, oldLine: string | null): string | null {
  const lines = text.split("\n");
  const idx = format === "sshd" ? lines.indexOf(newLine) : lines.lastIndexOf(newLine);
  if (idx < 0) return null;
  if (oldLine === null) lines.splice(idx, 1);
  else lines[idx] = oldLine;
  return lines.join("\n");
}
