// Process runner: argv arrays only (never a shell string), hard timeout, bounded output.

export const MAX_OUTPUT = 8 * 1024;

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export async function run(argv: string[], opts: { timeoutMs?: number; env?: Record<string, string> } = {}): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn(argv, {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, ...(opts.env ?? {}) } as Record<string, string>,
    });
  } catch (e) {
    return { code: 127, stdout: "", stderr: `spawn failed: ${(e as Error).message}`, timedOut: false };
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    proc.kill("SIGKILL");
  }, timeoutMs);
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout as ReadableStream).text(),
    new Response(proc.stderr as ReadableStream).text(),
    proc.exited,
  ]);
  clearTimeout(timer);
  return { code: timedOut ? 124 : code, stdout, stderr, timedOut };
}

/** Keep the tail (most informative for apt/nginx), bounded to 8KB. */
export function truncate(s: string, max = MAX_OUTPUT): string {
  if (s.length <= max) return s;
  return "...[truncated]...\n" + s.slice(s.length - (max - 20));
}

/** Privileged commands get `sudo -n` when the daemon is not root (VM install with sudoers drop-in). */
export function priv(argv: string[]): string[] {
  return process.getuid && process.getuid() !== 0 ? ["sudo", "-n", ...argv] : argv;
}

export function fmt(argv: string[], r: ExecResult): string {
  const out = [r.stdout.trim(), r.stderr.trim()].filter(Boolean).join("\n");
  return `$ ${argv.join(" ")}\n${out}${r.timedOut ? "\n[timed out]" : ""}${r.code !== 0 ? `\n[exit ${r.code}]` : ""}\n`;
}
