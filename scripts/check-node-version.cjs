// Keep this dependency-free: it runs before npm installs native modules and is
// bundled into the server so direct `node dist/index.cjs` starts are checked too.
function isSupportedNode(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!match) return false;
  const [, major, minor, patch] = match.map(Number);
  return major === 22 && (minor > 23 || (minor === 23 && patch >= 4));
}

if (!isSupportedNode(process.versions.node)) {
  throw new Error(
    `OptraSight requires Node.js >=22.23.4 <23 (October 2026 security fixes); found ${process.versions.node}. ` +
      "Install a supported Node 22 runtime, reinstall dependencies with npm ci, rebuild, and restart every platform process. " +
      "See docs/NODE_RUNTIME_SECURITY.md. No application startup was attempted.",
  );
}

module.exports = { isSupportedNode };
