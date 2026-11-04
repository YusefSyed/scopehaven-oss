// Node.js lines that run: each LTS line from its first release whose node:sqlite needs no flag and honours the open timeout the observers use. Keep equal to package.json
// "engines" and the launcher's scopehaven_engines / scopehaven_min_nodes (test/install-launcher.test.mjs checks all three).
export const SUPPORTED_NODE_LINES = Object.freeze({ 22: '22.16.0', 24: '24.0.0' });
// Each line's October 2026 security release. Below it the launcher warns and still runs. Keep equal to the launcher's
// scopehaven_security_nodes.
export const SECURITY_NODE_LINES = Object.freeze({ 22: '22.23.4', 24: '24.22.1' });
export const NODE_ENGINES = Object.entries(SUPPORTED_NODE_LINES).map(([major, floor]) => `>=${floor} <${Number(major) + 1}`).join(' || ');
export const SUPPORTED_NODE_TEXT = Object.entries(SUPPORTED_NODE_LINES).map(([major, floor]) => `Node.js ${major} LTS at ${floor} or newer`).join(', or ');
export function assertRuntime(version = process.versions.node) {
  const parts = /^([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(version);
  const [major, minor, patch] = parts ? parts.slice(1).map(Number) : [];
  const floor = parts ? SUPPORTED_NODE_LINES[major] : undefined;
  const [, needMinor, needPatch] = floor ? floor.split('.').map(Number) : [];
  if (!floor || minor < needMinor || (minor === needMinor && patch < needPatch)) {
    throw new Error(`Scopehaven requires ${SUPPORTED_NODE_TEXT} (engines ${NODE_ENGINES}); this runtime is ${parts ? `v${version}` : JSON.stringify(version)}. Use ./scopehaven, which selects a supported runtime, or get one from https://nodejs.org/en/download; the global Node installation is not changed.`);
  }
}
