// Prompt audit: Sentinel must carry no CVE-, scenario- or product-specific knowledge in its prompts or scan code.
// Scans apps/brain/src for forbidden strings and fails (exit 1) on any hit outside the explicit allow-list below.
// Usage: bun run prompt-audit
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dir, "..");
const SCAN_DIR = join(ROOT, "apps/brain/src");

const FORBIDDEN: { name: string; re: RegExp }[] = [
  { name: "CVE id", re: /CVE-\d{4}-\d+/i },
  { name: "scenario name", re: /php2shell/i },
  { name: "scenario name", re: /regresshion/i },
  { name: "product name", re: /openssh/i },
  { name: "CVE-specific mitigation", re: /logingracetime/i },
  { name: "CVE-specific mitigation", re: /multipart/i },
  { name: "CVE-specific mitigation", re: /memory_limit/i },
  { name: "product package", re: /php8\.3/i },
  { name: "fixed version", re: /8\.3\.36/ },
];

/**
 * Explicit exceptions: [file (relative to repo root), line regex, justification]. Each must be narrow.
 * Action type names come from the shared action catalog (packages/shared) — they are the daemon's API,
 * not CVE knowledge, and are needed to describe / roll back those actions.
 */
const ALLOW: { file: string; line: RegExp; why: string }[] = [
  { file: "apps/brain/src/actions.ts", line: /case "nginx_block_multipart":/, why: "human description of a shared-catalog action type" },
  { file: "apps/brain/src/demo.ts", line: /const REVERTIBLE = new Set\(\[.*"nginx_block_multipart"/, why: "shared-catalog action type name (demo reset rolls it back)" },
];

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : /\.(ts|tsx|js|mjs|json|md|txt)$/.test(n) ? [p] : [];
  });
}

const hits: { file: string; line: number; name: string; text: string }[] = [];
const allowed: { file: string; line: number; why: string }[] = [];
const used = new Set<number>();
let files = 0;
for (const path of walk(SCAN_DIR)) {
  files++;
  const rel = relative(ROOT, path);
  readFileSync(path, "utf8").split("\n").forEach((text, i) => {
    for (const f of FORBIDDEN) {
      if (!f.re.test(text)) continue;
      const a = ALLOW.findIndex((x) => x.file === rel && x.line.test(text));
      if (a >= 0) { used.add(a); allowed.push({ file: rel, line: i + 1, why: ALLOW[a]!.why }); }
      else hits.push({ file: rel, line: i + 1, name: f.name, text: text.trim().slice(0, 160) });
    }
  });
}

console.log(`prompt-audit: scanned ${files} files under ${relative(ROOT, SCAN_DIR)} for ${FORBIDDEN.length} forbidden patterns`);
for (const a of allowed) console.log(`  allowed  ${a.file}:${a.line} — ${a.why}`);
ALLOW.forEach((a, i) => { if (!used.has(i)) console.log(`  (unused allow-list entry: ${a.file} ${a.line})`); });
if (hits.length) {
  console.error(`\nFAIL: ${hits.length} forbidden string(s) found:`);
  for (const h of hits) console.error(`  ${h.file}:${h.line}  [${h.name}]  ${h.text}`);
  process.exit(1);
}
console.log("PASS: no CVE ids, scenario names or product-specific mitigation strings in Sentinel's prompts or scan code.");
