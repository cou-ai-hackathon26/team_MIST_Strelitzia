// Named osquery queries. The network may ONLY reference these names; the daemon owns the SQL.
// Raw SQL or shell is never accepted over the wire.

export const QUERY_NAMES = [
  "packages",        // InstalledPackage[]  (deb_packages: name, version, source, arch)
  "os_version",      // OsInfo (single row)
  "listening_ports", // ListeningPort[]     (listening_ports JOIN processes)
  "processes",       // {name,path,pid}[]
  "php_config",      // { key, value }[]    selected php.ini directives for every installed SAPI
  "firewall_rules",  // FirewallRule[]  ports currently closed by Prohori-managed rules (+ whether firewall tooling is available)
  "nginx_config",    // { key, value }[]    selected nginx directives (client_max_body_size, multipart block marker)
  "config_file",     // { key, value }[]    effective directives of ONE allow-listed config file; requires params.path (see CONFIG_PATHS)
  "services",        // { name, state }[]   init/systemd services and whether they are running
  "package_files",   // { path }[]          files shipped by ONE installed binary package (dpkg -L); requires params.package
] as const;

export type QueryName = (typeof QUERY_NAMES)[number];

/**
 * Config files the daemon may read via the `config_file` query (glob patterns; the daemon enforces this list).
 * Reading is read-only; values are returned as parsed key/value directives (comments stripped).
 */
export const CONFIG_PATHS = [
  "/etc/php/*/*/php.ini",
  "/etc/nginx/nginx.conf",
  "/etc/nginx/sites-enabled/*",
  "/etc/nginx/sites-available/*",
  "/etc/nginx/conf.d/*.conf",
  "/etc/ssh/sshd_config",
  "/etc/ssh/sshd_config.d/*.conf",
  "/etc/apache2/apache2.conf",
  "/etc/mysql/my.cnf",
  "/etc/redis/redis.conf",
] as const;

/** php.ini directives the daemon reports (relevant to PHP2Shell partial mitigations). */
export const PHP_DIRECTIVES = [
  "memory_limit",
  "post_max_size",
  "upload_max_filesize",
  "max_input_nesting_level",
  "max_input_vars",
  "file_uploads",
  "expose_php",
] as const;
