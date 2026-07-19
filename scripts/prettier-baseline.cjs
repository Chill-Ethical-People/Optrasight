#!/usr/bin/env node
const { execFileSync, spawnSync } = require("node:child_process");

const baseline = Number(process.env.OPTRASIGHT_PRETTIER_BASELINE || "0");
const verbose = process.env.OPTRASIGHT_PRETTIER_VERBOSE === "1" || process.argv.includes("--verbose");
const trackedFiles = execFileSync("git", ["ls-files", "-z"], { encoding: "buffer" })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

const result = spawnSync(
  process.platform === "win32" ? "npx.cmd" : "npx",
  ["prettier", "--check", ...trackedFiles],
  { encoding: "utf8" },
);
const output = `${result.stdout || ""}${result.stderr || ""}`;
const filesNeedingFormat = (output.match(/^\[warn\] .+$/gm) || []).filter(
  (line) => !line.includes("Code style issues found"),
).length;

if (filesNeedingFormat === 0) {
  process.stdout.write("Prettier check passed with 0 files needing formatting.\n");
  process.exit(0);
}

process.stdout.write(`Prettier files needing formatting: ${filesNeedingFormat}`);
if (baseline > 0) process.stdout.write(` (baseline: ${baseline})`);
process.stdout.write("\n");

if (verbose) process.stdout.write(output);

if (baseline <= 0 || filesNeedingFormat > baseline) {
  process.stderr.write(
    baseline > 0
      ? `Prettier deviation count increased above baseline ${baseline}. Run npm run format on the affected files.\n`
      : "Set OPTRASIGHT_PRETTIER_BASELINE to freeze the current formatting debt while it is reduced.\n",
  );
  process.exit(1);
}

process.stdout.write("Prettier baseline gate passed; formatting debt did not grow.\n");
