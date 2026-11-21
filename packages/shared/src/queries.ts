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
] as const;

export type QueryName = (typeof QUERY_NAMES)[number];

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
