#!/usr/bin/env node
// Verify chat converse + chat triage live behaviour against running server.
const http = require("http");

function req(path, body, token) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : "";
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const r = http.request({ host: "localhost", port: 5000, path, method: body ? "POST" : "GET", headers, timeout: 200000 }, (res) => {
      let buf = "";
      res.on("data", (c) => (buf += c));
      res.on("end", () => resolve({ status: res.statusCode, body: buf }));
    });
    r.on("error", reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  const t0 = Date.now();
  const login = await req("/api/v1/auth/login", { email: "admin@brandguard.local", password: "admin1234" });
  const token = JSON.parse(login.body).access_token;
  console.log("login OK", token.slice(0, 8));

  // Pick a finding for context.
  const f = await req("/api/v1/osint/findings?limit=3", null, token);
  const findingIds = JSON.parse(f.body).findings.map((x) => x.id).slice(0, 3);
  console.log("context findings:", findingIds);

  // converse
  console.log("=== chat/converse ===");
  const cStart = Date.now();
  const c = await req("/api/v1/osint/chat/converse", {
    messages: [
      { role: "user", content: "In two sentences only: what is the most severe finding currently in scope and the single best mitigation?" },
    ],
    contextFindingIds: findingIds,
  }, token);
  console.log(`status=${c.status} latency=${Date.now() - cStart}ms`);
  console.log("body:", c.body.slice(0, 600));

  // triage (range=24h)
  console.log("\n=== chat/triage ===");
  const tStart = Date.now();
  const tr = await req("/api/v1/osint/chat/triage", { range: "1d", maxItems: 20 }, token);
  console.log(`status=${tr.status} latency=${Date.now() - tStart}ms`);
  console.log("body:", tr.body.slice(0, 400));

  console.log(`\nTotal ${Date.now() - t0}ms`);
})().catch((e) => { console.error(e); process.exit(1); });
