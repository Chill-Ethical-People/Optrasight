import { build as esbuild } from "esbuild";
import { build as viteBuild } from "vite";
import { rm, readFile, mkdir, cp } from "node:fs/promises";
import { existsSync } from "node:fs";

// server deps to bundle to reduce openat(2) syscalls
// which helps cold start times
const allowlist = [
  "@google/generative-ai",
  "axios",
  "cors",
  "date-fns",
  "drizzle-orm",
  "drizzle-zod",
  "express",
  "express-rate-limit",
  "express-session",
  "jsonwebtoken",
  "memorystore",
  "multer",
  "nanoid",
  "nodemailer",
  "openai",
  "passport",
  "passport-local",
  "stripe",
  "uuid",
  "ws",
  "xlsx",
  "zod",
  "zod-validation-error",
];

async function buildAll() {
  await rm("dist", { recursive: true, force: true });

  console.log("building client...");
  await viteBuild();

  console.log("building server...");
  const pkg = JSON.parse(await readFile("package.json", "utf-8"));
  const allDeps = [
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {}),
  ];
  const externals = allDeps.filter((dep) => !allowlist.includes(dep));

  await esbuild({
    entryPoints: ["server/index.ts"],
    platform: "node",
    bundle: true,
    format: "cjs",
    outfile: "dist/index.cjs",
    define: {
      "process.env.NODE_ENV": '"production"',
    },
    minify: true,
    external: externals,
    logLevel: "info",
  });

  // v2.12: copy queryGrammars/*.md into dist so the hunt-query system prompt
  // can read the platform-specific grammar references at runtime.
  if (existsSync("server/queryGrammars")) {
    await mkdir("dist/queryGrammars", { recursive: true });
    await cp("server/queryGrammars", "dist/queryGrammars", { recursive: true });
    console.log("copied queryGrammars/ → dist/queryGrammars/");
  }

  // v2.28: copy server/data/*.json (typeahead dictionaries) into dist so
  // the /api/v1/osint/dictionaries endpoint can serve them in production.
  if (existsSync("server/data")) {
    await mkdir("dist/data", { recursive: true });
    await cp("server/data", "dist/data", { recursive: true });
    console.log("copied data/ → dist/data/");
  }
}

buildAll().catch((err) => {
  console.error(err);
  process.exit(1);
});
