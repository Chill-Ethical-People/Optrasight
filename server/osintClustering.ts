/**
 * v2.30 — Rule-based dedup clustering for osint_findings.
 *
 * Goal: group near-duplicate findings (same incident, same campaign, same
 * advisory) reported by different sources so the Sources Analytics dashboard
 * can compute unique-finding-rate, first-to-publish, and a co-occurrence
 * matrix — and so the Threat Actors / Campaigns page (v2.30.3) has a stable
 * `cluster_id` to aggregate on.
 *
 * Design constraints:
 *  - Deterministic, no AI cost.
 *  - Idempotent: re-running over the same row produces the same cluster_id.
 *  - Cross-tenant: a single physical incident may surface in multiple tenant
 *    feeds. Clusters are GLOBAL (not tenant-scoped) so analytics can answer
 *    "which sources are noisy" regardless of tenant filtering.
 *
 * Matching signal, in priority order:
 *   1) Shared "strong" IoC (sha256 > sha1 > md5 > url > ipv4 > domain > btc > email)
 *      within a 14-day window. Strong hits are enough on their own.
 *   2) Shared CVE id within a 14-day window. Strong on its own.
 *   3) Title similarity ≥ 0.85 (jaccard on lowercase token bag, ≥4 tokens both)
 *      AND a shared sector OR a shared affected_tech entry. Title alone is
 *      too loose for "Operation X" reposts; combined with a content anchor
 *      it's reliable.
 *
 * Cluster id format: `clu_<14-byte hex>` — uses the SHA-1 of the first strong
 * anchor seen for the cluster, so the id is stable.
 */

import crypto from "node:crypto";
import type Database from "better-sqlite3";

const CLUSTER_WINDOW_DAYS = 14;
const TITLE_SIM_THRESHOLD = 0.85;

/** Compute a normalised, lowercase, alpha-numeric token bag. */
function tokenize(text: string): Set<string> {
  const tokens = String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 3);
  return new Set(tokens);
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter += 1;
  const union = a.size + b.size - inter;
  return union > 0 ? inter / union : 0;
}

/** Parse JSON column safely → array of strings. */
function safeArr(raw: unknown): string[] {
  if (raw == null) return [];
  try {
    const v = JSON.parse(String(raw));
    return Array.isArray(v) ? v.map(String) : [];
  } catch { return []; }
}

/** Parse IoCs JSON → array of {kind,value} tuples. */
function flattenIocs(raw: unknown): Array<{ kind: string; value: string }> {
  if (raw == null) return [];
  let obj: any = {};
  try { obj = JSON.parse(String(raw)); } catch { return []; }
  if (!obj || typeof obj !== "object") return [];
  const out: Array<{ kind: string; value: string }> = [];
  const KINDS = ["sha256","sha1","md5","url","ipv4","domain","btc","email","ipv6"];
  for (const k of KINDS) {
    const arr = obj[k];
    if (!Array.isArray(arr)) continue;
    for (const v of arr) {
      const s = String(v || "").trim().toLowerCase();
      if (!s) continue;
      out.push({ kind: k, value: s });
    }
  }
  return out;
}

/** SHA-1 of a stable anchor string → 14-char hex id with prefix. */
function clusterIdFromAnchor(anchor: string): string {
  const hex = crypto.createHash("sha1").update(anchor).digest("hex");
  return `clu_${hex.slice(0, 14)}`;
}

/** Row shape we need from osint_findings for clustering. */
interface ClusterCandidateRow {
  id: string;
  title: string;
  published_at: string;
  cluster_id: string | null;
  iocs: string | null;
  cve_ids: string | null;
  sectors: string | null;
  affected_tech: string | null;
}

/**
 * Try to attach the given finding (by id) to an existing cluster, OR create a
 * new cluster id. Returns the assigned cluster id (always non-null after this
 * function — the caller persists it). Pure function over the database; no
 * commits — runs inside the calling transaction if any.
 */
export function assignClusterId(sqlite: Database.Database, fid: string): string | null {
  const row = sqlite.prepare(
    `SELECT id, title, published_at, cluster_id, iocs, cve_ids, sectors, affected_tech
     FROM osint_findings WHERE id = ?`
  ).get(fid) as ClusterCandidateRow | undefined;
  if (!row) return null;
  if (row.cluster_id) return row.cluster_id; // idempotent

  const iocs = flattenIocs(row.iocs);
  const cves = safeArr(row.cve_ids).map((s) => String(s).toUpperCase());
  const sectors = safeArr(row.sectors);
  const tech = safeArr(row.affected_tech).map((s) => s.toLowerCase());
  const titleTokens = tokenize(row.title);

  // Find candidate cluster ids by matching on strong anchors within the window.
  const windowFrom = (() => {
    const dt = new Date(row.published_at);
    if (isNaN(dt.getTime())) return null;
    return new Date(dt.getTime() - CLUSTER_WINDOW_DAYS * 86400_000).toISOString();
  })();
  const windowTo = (() => {
    const dt = new Date(row.published_at);
    if (isNaN(dt.getTime())) return null;
    return new Date(dt.getTime() + CLUSTER_WINDOW_DAYS * 86400_000).toISOString();
  })();
  if (!windowFrom || !windowTo) {
    // No usable timestamp — make a singleton cluster.
    return clusterIdFromAnchor(`single:${row.id}`);
  }

  const cands = sqlite.prepare(
    `SELECT id, title, published_at, cluster_id, iocs, cve_ids, sectors, affected_tech
     FROM osint_findings
     WHERE id != ?
       AND published_at >= ?
       AND published_at <= ?
       AND cluster_id IS NOT NULL
     ORDER BY published_at DESC
     LIMIT 500`
  ).all(row.id, windowFrom, windowTo) as ClusterCandidateRow[];

  // --- Signal 1 + 2: shared strong IoC or shared CVE ---
  const ourStrongValues = new Set(iocs.map((x) => `${x.kind}:${x.value}`));
  const ourCveSet = new Set(cves);

  for (const c of cands) {
    const candIocs = flattenIocs(c.iocs);
    for (const v of candIocs) {
      if (ourStrongValues.has(`${v.kind}:${v.value}`)) {
        // Strong match → reuse candidate's cluster.
        return c.cluster_id!;
      }
    }
    const candCves = safeArr(c.cve_ids).map((s) => String(s).toUpperCase());
    for (const cve of candCves) {
      if (ourCveSet.has(cve)) return c.cluster_id!;
    }
  }

  // --- Signal 3: title similarity + content anchor ---
  if (titleTokens.size >= 4) {
    let bestSim = 0;
    let bestCluster: string | null = null;
    for (const c of cands) {
      const candTokens = tokenize(c.title);
      if (candTokens.size < 4) continue;
      const sim = jaccard(titleTokens, candTokens);
      if (sim < TITLE_SIM_THRESHOLD) continue;
      // Need a shared sector OR a shared affected_tech to confirm.
      const candSectors = new Set(safeArr(c.sectors));
      const candTech = new Set(safeArr(c.affected_tech).map((s) => s.toLowerCase()));
      const sectorHit = sectors.some((s) => candSectors.has(s));
      const techHit = tech.some((t) => candTech.has(t));
      if (!sectorHit && !techHit) continue;
      if (sim > bestSim) { bestSim = sim; bestCluster = c.cluster_id; }
    }
    if (bestCluster) return bestCluster;
  }

  // No match — mint a new cluster, anchored on the first strongest IoC if
  // present, else on the finding id.
  if (iocs.length > 0) {
    const order = ["sha256","sha1","md5","url","ipv4","domain","btc","email","ipv6"];
    const first = iocs.slice().sort(
      (a, b) => order.indexOf(a.kind) - order.indexOf(b.kind),
    )[0];
    return clusterIdFromAnchor(`ioc:${first.kind}:${first.value}`);
  }
  if (cves.length > 0) return clusterIdFromAnchor(`cve:${cves.sort()[0]}`);
  return clusterIdFromAnchor(`fid:${row.id}`);
}

/**
 * Convenience: assign and persist cluster_id for one finding. Safe to call
 * repeatedly; if cluster_id already set, no-ops.
 */
export function ensureClusterIdPersisted(sqlite: Database.Database, fid: string): string | null {
  const existing = sqlite.prepare(
    `SELECT cluster_id FROM osint_findings WHERE id = ?`
  ).get(fid) as { cluster_id: string | null } | undefined;
  if (!existing) return null;
  if (existing.cluster_id) return existing.cluster_id;
  const cid = assignClusterId(sqlite, fid);
  if (!cid) return null;
  sqlite.prepare(`UPDATE osint_findings SET cluster_id = ? WHERE id = ? AND cluster_id IS NULL`).run(cid, fid);
  return cid;
}

/**
 * Bulk pass: assign cluster_id for every osint_findings row missing one.
 * Used by the v2.30 startup migration to backfill historical data, and by the
 * admin "Re-analyse last 30 days" job.
 *
 * Iterates oldest-first so that newer findings benefit from clusters formed
 * by their predecessors (otherwise the very first row of a campaign would
 * mint a singleton even though it was part of a real burst).
 */
export function backfillClusters(
  sqlite: Database.Database,
  opts?: { sinceIso?: string; limit?: number },
): { scanned: number; assigned: number } {
  const params: any[] = [];
  let where = "cluster_id IS NULL";
  if (opts?.sinceIso) { where += " AND published_at >= ?"; params.push(opts.sinceIso); }
  const limit = Math.max(1, Math.min(opts?.limit ?? 100000, 100000));
  const rows = sqlite.prepare(
    `SELECT id FROM osint_findings WHERE ${where} ORDER BY published_at ASC LIMIT ?`
  ).all(...params, limit) as Array<{ id: string }>;

  let assigned = 0;
  for (const r of rows) {
    const cid = ensureClusterIdPersisted(sqlite, r.id);
    if (cid) assigned += 1;
  }
  return { scanned: rows.length, assigned };
}
