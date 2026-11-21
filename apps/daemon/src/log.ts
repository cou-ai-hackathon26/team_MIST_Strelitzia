export function log(...args: unknown[]) {
  console.log(new Date().toISOString(), ...args);
}
export function warn(...args: unknown[]) {
  console.log(new Date().toISOString(), "WARN", ...args);
}
