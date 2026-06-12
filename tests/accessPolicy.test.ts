import assert from "node:assert/strict";
import { it } from "vitest";
import {
  hasCapability,
  isBatchOneApiAllowed,
  resolveCapabilities,
} from "../shared/accessPolicy";
import { aiJobCompleted, aiJobElapsed, aiJobFailed, aiJobOpenUrl } from "../client/src/lib/aiJobDisplay";
import { aiJobKindLabel, aiJobRowState } from "../client/src/components/AiJobsTray";
import { canRunAnalyzeNow, relativeTime } from "../client/src/components/OsintAutomationCard";
import {
  appShellAccessLabel,
  useReviewOnlyNav,
} from "../client/src/lib/appShellPolicy";
import { parseCirtDeepLink } from "../client/src/components/OsintTriagePanel";
import { resolveSessionAccessMode } from "../client/src/lib/auth";
import { batchOneRedirectFor, hashPath, stripHashQuery } from "../client/src/lib/batchOneRoutes";
import { BATCH_ONE_AI_TASKS } from "../shared/schema";
import {
  isOperationJobActive,
  isOperationJobComplete,
  isOperationJobFailed,
  operationJobProgress,
} from "../client/src/pages/OperationsAudit";

it("keeps BatchOne access policy and UI helpers stable", () => {
const review = resolveCapabilities({ role: "admin", accessMode: "guest", batchOne: true });
assert.equal(hasCapability(review, "view_intel"), true);
assert.equal(hasCapability(review, "task_analysis"), true);
assert.equal(hasCapability(review, "manage_sources"), false);
assert.equal(hasCapability(review, "tenant_pivot"), false);
assert.equal(hasCapability(review, "global_view"), false);

const operator = resolveCapabilities({ role: "admin", accessMode: "credentialed", batchOne: true });
assert.equal(hasCapability(operator, "manage_sources"), true);
assert.equal(hasCapability(operator, "configure_ai"), true);
assert.equal(hasCapability(operator, "tenant_pivot"), false);
assert.equal(hasCapability(operator, "global_view"), false);

const fullAdmin = resolveCapabilities({ role: "admin", accessMode: "credentialed", batchOne: false });
assert.equal(hasCapability(fullAdmin, "tenant_pivot"), true);
assert.equal(hasCapability(fullAdmin, "global_view"), true);

assert.equal(isBatchOneApiAllowed({ method: "GET", path: "/api/v1/osint/findings", accessMode: "guest" }), true);
assert.equal(isBatchOneApiAllowed({ method: "POST", path: "/api/v1/osint/sources/bulk", accessMode: "guest" }), false);
assert.equal(isBatchOneApiAllowed({ method: "POST", path: "/api/v1/osint/sources/bulk", accessMode: "credentialed" }), true);
assert.equal(isBatchOneApiAllowed({ method: "GET", path: "/api/v1/global/groups", accessMode: "credentialed" }), false);
assert.equal(isBatchOneApiAllowed({ method: "GET", path: "/api/v1/threat-actors-tenant-tags", accessMode: "credentialed" }), false);
assert.equal(isBatchOneApiAllowed({ method: "GET", path: "/api/v1/threat-actors/tap-001/tenants", accessMode: "credentialed" }), false);
assert.deepEqual([...BATCH_ONE_AI_TASKS], [
  "osint_analysis",
  "osint_overview",
  "osint_chat",
  "hunt_query",
  "threat_actor_enrichment",
  "tap_portrait",
]);

assert.equal(stripHashQuery("/osint?finding=abc"), "/osint");
assert.equal(stripHashQuery("?only=query"), "/");
assert.equal(hashPath("#/threat-actors?actor=tap-001"), "/threat-actors");
assert.equal(hashPath(""), "/");
assert.equal(batchOneRedirectFor("#/ai-setup", "guest"), "#/osint");
assert.equal(batchOneRedirectFor("#/ai-setup", "credentialed"), null);
assert.equal(batchOneRedirectFor("#/settings", "credentialed"), "#/osint");
assert.equal(batchOneRedirectFor("#/threat-actors?actor=tap-001", "guest"), null);

assert.equal(aiJobCompleted("completed"), true);
assert.equal(aiJobCompleted("failed"), false);
assert.equal(aiJobFailed("completed_with_errors"), true);
assert.equal(aiJobFailed("running"), false);
assert.equal(aiJobElapsed({
  createdAt: "2026-06-08T00:00:00.000Z",
  startedAt: "2026-06-08T00:00:00.000Z",
  completedAt: "2026-06-08T00:02:05.000Z",
}), "2m 5s");
assert.equal(aiJobOpenUrl({ kind: "chat_triage", targetUrl: "/#/osint?job=abc", resultBytes: 0 }), "/#/osint");
assert.equal(aiJobOpenUrl({ kind: "osint_analysis", targetUrl: "/#/osint?job=abc", resultBytes: 0 }), "/#/osint?job=abc");
assert.equal(aiJobKindLabel("chat_deep_dive"), "CIRT deep-dive");
assert.equal(aiJobKindLabel("unknown_kind"), "unknown kind");
assert.deepEqual(aiJobRowState({
  id: "job-1",
  kind: "chat_triage",
  status: "completed",
  progressPct: 100,
  createdAt: "2026-06-08T00:00:00.000Z",
  targetLabel: "CIRT triage",
  targetUrl: "/#/osint?ai=triage&job=job-1",
  resultBytes: 10,
}, "finished"), {
  kindLabel: "CIRT triage",
  target: "CIRT triage",
  ok: true,
  fail: false,
  openUrl: "/#/osint?ai=triage&job=job-1",
  isRunning: false,
});
assert.deepEqual(aiJobRowState({
  id: "job-2",
  kind: "finding_ai_triage",
  status: "running",
  progressPct: 25,
  createdAt: "2026-06-08T00:00:00.000Z",
}, "running"), {
  kindLabel: "Finding AI triage",
  target: "",
  ok: false,
  fail: false,
  openUrl: null,
  isRunning: true,
});

assert.deepEqual(parseCirtDeepLink("#/osint?ai=triage&job=abc"), { mode: "triage", jobId: "abc" });
assert.deepEqual(parseCirtDeepLink("#/osint?ai=deep-dive&job=def"), { mode: "deepdive", jobId: "def" });
assert.deepEqual(parseCirtDeepLink("#/osint?ai=deepdive"), { mode: "deepdive", jobId: null });
assert.equal(parseCirtDeepLink("#/osint?ai=overview&job=abc"), null);
assert.equal(parseCirtDeepLink("#/osint"), null);

assert.equal(resolveSessionAccessMode({ access_mode: "guest" }, {}, "credentialed"), "guest");
assert.equal(resolveSessionAccessMode({}, { accessMode: "guest" }, "credentialed"), "guest");
assert.equal(resolveSessionAccessMode({}, { access_mode: "credentialed" }, "guest"), "credentialed");
assert.equal(resolveSessionAccessMode({}, {}, "guest"), "guest");
assert.equal(canRunAnalyzeNow({ mutationPending: false, autoAnalyzeEnabled: true, aiDisabled: false }), true);
assert.equal(canRunAnalyzeNow({ mutationPending: true, autoAnalyzeEnabled: true, aiDisabled: false }), false);
assert.equal(canRunAnalyzeNow({ mutationPending: false, autoAnalyzeEnabled: false, aiDisabled: false }), false);
assert.equal(canRunAnalyzeNow({ mutationPending: false, autoAnalyzeEnabled: true, aiDisabled: true }), false);
assert.equal(relativeTime(null, Date.parse("2026-06-08T00:00:00.000Z")), "never");
assert.equal(relativeTime("2026-06-08T00:00:30.000Z", Date.parse("2026-06-08T00:00:00.000Z")), "just now");
assert.equal(relativeTime("2026-06-07T23:58:00.000Z", Date.parse("2026-06-08T00:00:00.000Z")), "2m ago");
assert.equal(isOperationJobActive("queued"), true);
assert.equal(isOperationJobActive("completed"), false);
assert.equal(isOperationJobComplete("done"), true);
assert.equal(isOperationJobFailed({ status: "completed", errorMessage: "partial provider error" }), true);
assert.equal(operationJobProgress({ status: "completed", progressPct: 0, errorMessage: null }), 100);
assert.equal(operationJobProgress({ status: "completed", progressPct: 0, errorMessage: "provider failed" }), 0);
assert.equal(operationJobProgress({ status: "running", progressPct: 140, errorMessage: null }), 100);
assert.equal(operationJobProgress({ status: "running", progressPct: -5, errorMessage: null }), 5);
assert.equal(operationJobProgress({ status: "failed", progressPct: -5, errorMessage: "provider failed" }), 0);

assert.equal(appShellAccessLabel({ batchOne: true, accessMode: "guest", role: "admin", tenantName: "Acme" }), "Read-only reviewer");
assert.equal(appShellAccessLabel({ batchOne: true, accessMode: "credentialed", role: "admin", tenantName: "Acme" }), "Threat analyst");
assert.equal(appShellAccessLabel({ batchOne: false, role: "admin", tenantName: "Acme" }), "Platform admin");
assert.equal(appShellAccessLabel({ batchOne: false, role: "analyst", tenantName: "Acme" }), "Acme");
assert.equal(useReviewOnlyNav({ batchOne: true, accessMode: "guest" }), true);
assert.equal(useReviewOnlyNav({ batchOne: true, accessMode: "credentialed" }), false);
});
