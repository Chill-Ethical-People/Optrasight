// Live diagnostic: kick off an OSINT AI analysis against the running server
// and inspect whether the response carries live AI fields or the mock label.
const http = require("http");
function req(method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: "127.0.0.1", port: 5000, method, path, headers: { "Content-Type": "application/json", ...(headers || {}) } }, (resp) => {
      let chunks = "";
      resp.on("data", (d) => (chunks += d));
      resp.on("end", () => resolve({ status: resp.statusCode, body: chunks }));
    });
    r.on("error", reject);
    if (body) r.write(typeof body === "string" ? body : JSON.stringify(body));
    r.end();
  });
}

(async () => {
  const login = await req("POST", "/api/v1/auth/login", {}, {
    email: process.env.OPTRASIGHT_DIAG_EMAIL || "admin@cep.com",
    password: process.env.OPTRASIGHT_DIAG_PASSWORD || "ChangeMe!2026Admin",
  });
  console.log("login:", login.status, login.body.slice(0, 200));
  const tok = JSON.parse(login.body).access_token;
  const A = { Authorization: `Bearer ${tok}` };
  // Pick a finding that has NOT yet been AI-analyzed (cleared by v2.23 backfill — many available)
  const list = await req("GET", "/api/v1/osint/findings?limit=20", A);
  const items = JSON.parse(list.body).items || JSON.parse(list.body);
  const findings = (Array.isArray(items) ? items : (items.items || items.findings || []));
  console.log("findings count:", findings.length);
  if (!findings.length) return;
  const target = findings.find((f) => !f.aiSummary && !f.ai_summary) || findings[0];
  console.log("target id:", target.id, "url:", target.url);
  // POST ai-analyze with onlyUnanalyzed=true so it processes just this one
  const start = Date.now();
  const ana = await req("POST", "/api/v1/osint/findings/ai-analyze", A, { ids: [target.id], onlyUnanalyzed: false });
  console.log("analyze.status:", ana.status, `(${Date.now() - start}ms)`);
  console.log("analyze.body:\n", ana.body.slice(0, 3000));
  // Then re-fetch the finding to see its new aiSummary / aiProviderLabel
  const refetch = await req("GET", `/api/v1/osint/findings/${target.id}`, A);
  try {
    const j = JSON.parse(refetch.body);
    console.log("\n--- refetched finding ---");
    console.log("aiProviderLabel:", j.aiProviderLabel || j.ai_provider_label);
    console.log("aiSummary[0..400]:", (j.aiSummary || j.ai_summary || "").slice(0, 400));
    console.log("aiRelevanceScore:", j.aiRelevanceScore || j.ai_relevance_score);
    console.log("iocs:", JSON.stringify(j.iocs).slice(0, 400));
  } catch (e) { console.log("refetch parse err:", e.message); }
})().catch((e) => { console.error("ERR:", e); process.exit(1); });
