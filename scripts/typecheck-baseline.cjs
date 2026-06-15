#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const baseline = Number(process.env.OPTRASIGHT_TSC_BASELINE || "0");
const result = spawnSync(
  process.platform === "win32" ? "npx.cmd" : "npx",
  ["tsc", "--noEmit", "--pretty", "false", "--incremental", "false"],
  { encoding: "utf8" },
);

const output = `${result.stdout || ""}${result.stderr || ""}`;
const errors = (output.match(/\berror TS\d+:/g) || []).length;

if (errors === 0) {
  process.stdout.write("TypeScript check passed with 0 errors.\n");
  process.exit(0);
}

process.stdout.write(output);
process.stdout.write(`\nTypeScript errors: ${errors}`);
if (baseline > 0) process.stdout.write(` (baseline: ${baseline})`);
process.stdout.write("\n");

if (baseline <= 0 || errors > baseline) {
  process.stderr.write(
    baseline > 0
      ? `TypeScript error count increased above baseline ${baseline}.\n`
      : "Set OPTRASIGHT_TSC_BASELINE to freeze the current debt while burning it down.\n",
  );
  process.exit(1);
}

process.stdout.write("TypeScript baseline gate passed; existing debt did not grow.\n");
