import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";

const require = createRequire(import.meta.url);
const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const { isSupportedNode } = require("../scripts/check-node-version.cjs");

describe("Node runtime security policy", () => {
  it.each(["22.23.4", "22.23.5", "22.24.0", "22.100.0"])("accepts patched Node %s", (version) => {
    expect(isSupportedNode(version)).toBe(true);
  });

  it.each([
    "18.20.8",
    "20.20.0",
    "22.0.0",
    "22.22.99",
    "22.23.3",
    "23.0.0",
    "24.22.1",
    "25.6.1",
    "26.12.1",
    "22.23.4-rc.1",
    "22.23",
    "not-a-version",
  ])("rejects unsupported or unvalidated Node %s", (version) => {
    expect(isSupportedNode(version)).toBe(false);
    expect(() =>
      runInNewContext(read("scripts/check-node-version.cjs"), {
        process: { versions: { node: version } },
        module: { exports: {} },
      }),
    ).toThrow("OptraSight requires Node.js >=22.23.4 <23");
  });

  it("runs without application dependencies on the actual runtime", () => {
    expect(isSupportedNode(process.versions.node)).toBe(true);
    expect(() =>
      runInNewContext(read("scripts/check-node-version.cjs"), {
        process: { versions: { node: process.versions.node } },
        module: { exports: {} },
      }),
    ).not.toThrow();
  });

  it("keeps install, startup, container and release runtime requirements aligned", () => {
    const pkg = JSON.parse(read("package.json"));
    const lock = JSON.parse(read("package-lock.json"));
    const minimum = read(".nvmrc").trim();
    expect(minimum).toBe("22.23.4");
    expect(pkg.engines.node).toBe(`>=${minimum} <23`);
    expect(lock.packages[""].engines.node).toBe(pkg.engines.node);
    expect(read(".npmrc")).toContain("engine-strict=true");
    for (const hook of ["preinstall", "predev", "prestart", "prebuild"]) {
      expect(pkg.scripts[hook]).toContain("npm run check:node");
    }
    expect(read("server/index.ts").split("\n")[0]).toBe('import "../scripts/check-node-version.cjs";');
    const docker = read("Dockerfile");
    expect(docker.match(/^FROM .+$/gm)).toEqual([
      `FROM node:${minimum}-alpine AS builder`,
      `FROM node:${minimum}-alpine`,
    ]);
    expect(docker.indexOf("COPY scripts/check-node-version.cjs")).toBeLessThan(docker.indexOf("RUN npm ci"));
    const release = read(".github/workflows/release.yml");
    expect(release).toContain(`- "${minimum}"`);
    expect(release).toContain('- "22.x"');
    expect(release).not.toContain('"20.x"');
    expect(release).toContain("package-lock.json .env.example .npmrc .nvmrc");
    expect(release).toContain('cp -R scripts "${RELEASE_DIR}/scripts"');
    expect(read(".github/workflows/pages.yml")).toContain("node-version-file: .nvmrc");
  });
});

describe("native dependencies under the supported runtime", () => {
  it("supports SQLite reads, writes and rollback without using a platform database", () => {
    const Database = require("better-sqlite3");
    const db = new Database(":memory:");
    try {
      db.exec("CREATE TABLE runtime_check (id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
      db.prepare("INSERT INTO runtime_check(value) VALUES (?)").run("security smoke test");
      expect(db.prepare("SELECT value FROM runtime_check WHERE id = 1").get()).toEqual({
        value: "security smoke test",
      });
      expect(() =>
        db.transaction(() => {
          db.prepare("UPDATE runtime_check SET value = ? WHERE id = 1").run("uncommitted");
          throw new Error("rollback smoke test");
        })(),
      ).toThrow("rollback smoke test");
      expect(db.prepare("SELECT value FROM runtime_check WHERE id = 1").get()).toEqual({
        value: "security smoke test",
      });
    } finally {
      db.close();
    }
  });

  it("supports native image processing without touching stored portraits", async () => {
    const sharp = require("sharp");
    const image = await sharp({ create: { width: 8, height: 8, channels: 3, background: "#445566" } })
      .resize(4, 4)
      .png()
      .toBuffer();
    const metadata = await sharp(image).metadata();
    expect(metadata).toMatchObject({ width: 4, height: 4, format: "png" });
  });
});
