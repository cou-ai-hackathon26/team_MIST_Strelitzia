import { z } from "zod";

// Tier-2 remediation allowlist. The daemon enforces this list locally and validates params itself.
// The AI may only PROPOSE these; a human approves in the dashboard.

export const ActionParams = {
  /**
   * PRIMARY demo mitigation. Close or re-open one port in the host firewall (iptables INPUT rules tagged
   * with comment "prohori"; the daemon only ever adds/removes rules carrying that tag).
   * Port 22 is refused (never lock admins out). Closing a port removes network exposure of the service on it.
   */
  firewall_port: z.object({
    port: z.number().int().min(1).max(65535).refine((p) => p !== 22, "port 22 (SSH) is never managed by Prohori"),
    protocol: z.enum(["tcp", "udp"]),
    state: z.enum(["closed", "open"]),
  }),
  /** apt-get install --only-upgrade <packages>; records previous versions for rollback. The complete fix for PHP2Shell. */
  upgrade_packages: z.object({
    packages: z.array(z.string().regex(/^[a-z0-9][a-z0-9+.-]+$/)).min(1).max(20),
  }),
  /** Interim partial mitigation: nginx rejects multipart/form-data requests (returns 415). Reversible. */
  nginx_block_multipart: z.object({}),
  /** Set a php.ini directive for one SAPI (allowlisted directives only), then restart that SAPI. */
  set_php_directive: z.object({
    sapi: z.enum(["fpm", "cli", "apache2"]),
    directive: z.enum(["post_max_size", "max_input_nesting_level", "max_input_vars", "file_uploads", "memory_limit"]),
    value: z.string().regex(/^[A-Za-z0-9-]{1,10}$/),
  }),
  /**
   * Generic, allow-listed config change: set one directive in one config file, then reload/restart the owning
   * service. The DAEMON holds the allow-list of (file pattern, directive, service) — see CONFIG_DIRECTIVE_ALLOWLIST.
   * Reversible (the previous line is kept for rollback).
   */
  set_config_directive: z.object({
    file: z.string().regex(/^\/etc\/[A-Za-z0-9_.\/*-]{1,120}$/),
    directive: z.string().regex(/^[A-Za-z][A-Za-z0-9_.]{0,63}$/),
    value: z.string().regex(/^[A-Za-z0-9 :._\/-]{1,40}$/),
  }),
  /** Restart an allowlisted service. */
  restart_service: z.object({
    service: z.enum(["nginx", "php8.3-fpm", "ssh"]),
  }),
} as const;

export type ActionType = keyof typeof ActionParams;
export const ACTION_TYPES = Object.keys(ActionParams) as ActionType[];

export const ACTION_DESCRIPTIONS: Record<ActionType, string> = {
  firewall_port: "Close (or re-open) one port in the host firewall. Removes network exposure of the service on that port; the service becomes unreachable. Reversible.",
  upgrade_packages: "Upgrade the listed packages to the latest available distro build (complete fix when a patched build exists).",
  nginx_block_multipart: "Make nginx reject multipart/form-data requests (partial, interim mitigation; breaks file uploads).",
  set_php_directive: "Change one allowlisted php.ini directive for one SAPI and restart it (partial mitigation).",
  set_config_directive: "Set one allow-listed directive in one config file (e.g. a php.ini limit or an sshd_config option) and restart the owning service. Usually a partial mitigation; reversible.",
  restart_service: "Restart nginx, php8.3-fpm or ssh.",
};

/**
 * Directives the daemon allows `set_config_directive` to change, per config file pattern, and the service it
 * restarts afterwards. Shared so Sentinel's remediation planner knows what is possible; the daemon enforces it.
 */
export const CONFIG_DIRECTIVE_ALLOWLIST: { file: string; directives: string[]; service: string }[] = [
  { file: "/etc/php/*/fpm/php.ini", directives: ["post_max_size", "max_input_nesting_level", "max_input_vars", "file_uploads", "memory_limit", "upload_max_filesize"], service: "php8.3-fpm" },
  { file: "/etc/php/*/cli/php.ini", directives: ["post_max_size", "max_input_nesting_level", "max_input_vars", "file_uploads", "memory_limit"], service: "" },
  { file: "/etc/ssh/sshd_config", directives: ["LoginGraceTime", "MaxStartups", "PermitRootLogin", "PasswordAuthentication"], service: "ssh" },
];
