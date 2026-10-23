// Run only after building. Always starts its own server against disposable data;
// never accepts a live server URL or an existing database path.
const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const { once } = require("node:events");
const { mkdtempSync, rmSync, existsSync, readdirSync } = require("node:fs");
const { createRequire } = require("node:module");
const { createServer } = require("node:net");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { randomBytes } = require("node:crypto");
require(resolve("scripts/check-node-version.cjs"));

async function main() {
  const bundle = resolve("dist/index.cjs");
  assert.ok(existsSync(bundle), "Run npm run build before the runtime smoke check.");
  const rejectedScratch = mkdtempSync(join(tmpdir(), "optrasight-runtime-rejection-"));
  try {
    const rejected = spawnSync(
      process.execPath,
      [
        "-e",
        'Object.defineProperty(process.versions, "node", { value: "22.23.3" }); require(process.argv[1]);',
        bundle,
      ],
      {
        cwd: rejectedScratch,
        encoding: "utf8",
        timeout: 10000,
        maxBuffer: 4 * 1024 * 1024,
        env: { NODE_ENV: "production" },
      },
    );
    assert.equal(rejected.status, 1, "Compiled server must reject an older Node version.");
    assert.match(rejected.stderr, /OptraSight requires Node.js >=22\.23\.4 <23/);
    assert.deepEqual(readdirSync(rejectedScratch), [], "Runtime rejection must precede database initialization.");
  } finally {
    rmSync(rejectedScratch, { recursive: true, force: true });
  }
  const appRequire = createRequire(bundle);
  const Database = appRequire("better-sqlite3");
  const db = new Database(":memory:");
  try {
    assert.equal(db.prepare("SELECT 1 AS ok").get().ok, 1);
  } finally {
    db.close();
  }
  const sharp = appRequire("sharp");
  const png = await sharp({ create: { width: 4, height: 4, channels: 3, background: "#445566" } })
    .png()
    .toBuffer();
  assert.equal((await sharp(png).metadata()).width, 4);

  const reservation = createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise((resolveClose) => reservation.close(resolveClose));
  const scratch = mkdtempSync(join(tmpdir(), "optrasight-runtime-smoke-"));
  const child = spawn(process.execPath, [bundle], {
    cwd: scratch,
    env: {
      PATH: process.env.PATH,
      ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
      NODE_ENV: "production",
      OPTRASIGHT_STRICT: "1",
      OPTRASIGHT_KEY_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
      PORT: String(port),
    },
    stdio: "ignore",
  });
  let launchError;
  child.on("error", (error) => {
    launchError = error;
  });
  const exited = new Promise((resolveExit) => child.once("close", resolveExit));
  const request = (path, options = {}) =>
    fetch(`http://127.0.0.1:${port}${path}`, {
      ...options,
      signal: AbortSignal.timeout(3000),
    });
  try {
    let ready = false;
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if (launchError) throw launchError;
      assert.equal(child.exitCode, null, "Isolated production server exited before becoming healthy.");
      try {
        const response = await request("/api/v1/health");
        if (response.ok) {
          const health = await response.json();
          assert.equal(health.service, "optrasight");
          assert.equal(health.strict, true);
          assert.equal(health.nodeEnv, "production");
          ready = true;
          break;
        }
      } catch (error) {
        if (error.code === "ERR_ASSERTION") throw error;
      }
      await new Promise((resolveWait) => setTimeout(resolveWait, 200));
    }
    assert.ok(ready, "Isolated server did not become healthy within 30 seconds.");
    const page = await request("/");
    assert.equal(page.status, 200);
    assert.match(await page.text(), /id=["']root["']/);
    assert.ok(page.headers.get("content-security-policy"));
    for (const path of [
      "/api/v1/me",
      "/api/v1/osint/findings",
      "/api/v1/osint/sources",
      "/api/v1/ai/providers",
      "/api/v1/threat-actors",
    ]) {
      assert.equal((await request(path)).status, 401, `Authentication boundary changed: ${path}`);
    }
    const denied = await request("/api/v1/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "runtime-smoke@example.invalid", password: randomBytes(24).toString("hex") }),
    });
    assert.equal(denied.status, 401);
    console.log(
      `Runtime smoke passed on Node ${process.versions.node}: native modules, production boot, strict health, UI delivery and authentication boundaries. No live AI/email tested.`,
    );
  } finally {
    child.kill("SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 5000);
    await exited;
    clearTimeout(force);
    rmSync(scratch, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
