import { describe, expect, it } from "vitest";
import { hasCapability, isBatchOneApiAllowed, resolveCapabilities } from "../shared/accessPolicy";
import { extractReferencedUrlsForTest, isPrivateOrReservedAddress, isSafeSourceFetchUrl } from "../server/sourceFetch";
import { aiProviderBaseUrlSyncFailure, validateAiProviderBaseUrl } from "../server/aiProviderSecurity";
import { isChatbotCodeDevelopmentRequest, runChatConverse } from "../server/osintChat";
import {
  ADMIN_SESSION_ABSOLUTE_MS,
  ADMIN_SESSION_IDLE_TIMEOUT_MS,
  SESSION_ABSOLUTE_MS,
  SESSION_IDLE_TIMEOUT_MS,
  sessionExpiryReason,
} from "../server/storage";

describe("security controls", () => {
  it("keeps BatchOne-only routes and capabilities scoped", () => {
    expect(isBatchOneApiAllowed({ method: "GET", path: "/api/v1/threat-actors/tap-001/tenants", accessMode: "credentialed" })).toBe(false);
    expect(isBatchOneApiAllowed({ method: "POST", path: "/api/v1/osint/findings/email-draft", accessMode: "credentialed" })).toBe(false);
    expect(hasCapability(resolveCapabilities({ role: "admin", accessMode: "credentialed", batchOne: true }), "global_view")).toBe(false);
    expect(hasCapability(resolveCapabilities({ role: "admin", accessMode: "credentialed", batchOne: false }), "global_view")).toBe(true);
  });

  it("blocks private and reserved outbound fetch targets", async () => {
    expect(isPrivateOrReservedAddress("127.0.0.1")).toBe(true);
    expect(isPrivateOrReservedAddress("10.10.10.10")).toBe(true);
    expect(isPrivateOrReservedAddress("172.16.1.20")).toBe(true);
    expect(isPrivateOrReservedAddress("192.168.1.5")).toBe(true);
    expect(isPrivateOrReservedAddress("169.254.169.254")).toBe(true);
    expect(isPrivateOrReservedAddress("8.8.8.8")).toBe(false);

    expect(await isSafeSourceFetchUrl("http://127.0.0.1:5000/api/v1/me")).toBe(false);
    expect(await isSafeSourceFetchUrl("http://169.254.169.254/latest/meta-data/")).toBe(false);
    expect(await isSafeSourceFetchUrl("http://localhost:5000/")).toBe(false);
    expect(await isSafeSourceFetchUrl("file:///etc/passwd")).toBe(false);
  });

  it("prioritizes high-signal source references for AI analysis context", () => {
    const refs = extractReferencedUrlsForTest(`
      <a href="/category/security">Category</a>
      <a href="https://twitter.com/example">Social</a>
      <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-1234">NVD</a>
      <a href="https://attack.mitre.org/techniques/T1059/">ATT&CK</a>
      <a href="https://vendor.example/security/advisory/cve-2026-1234">Vendor advisory</a>
    `, "https://news.example/article", 3);

    expect(refs).toEqual([
      "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
      "https://attack.mitre.org/techniques/T1059/",
      "https://vendor.example/security/advisory/cve-2026-1234",
    ]);
  });

  it("validates AI provider base URLs before outbound calls", async () => {
    expect(aiProviderBaseUrlSyncFailure("http://127.0.0.1:6379")).toBe("AI provider base URL must use HTTPS.");
    expect(aiProviderBaseUrlSyncFailure("https://127.0.0.1")).toBe("AI provider base URL cannot target private or reserved IP space.");
    expect(aiProviderBaseUrlSyncFailure("https://[::1]")).toBe("AI provider base URL cannot target private or reserved IP space.");
    expect(aiProviderBaseUrlSyncFailure("https://localhost")).toBe("AI provider base URL cannot target local or internal hosts.");
    expect(aiProviderBaseUrlSyncFailure("https://api.openai.com")).toBeNull();
    expect(await validateAiProviderBaseUrl("openai", "https://127.0.0.1")).toBe("AI provider base URL cannot target private or reserved IP space.");
  });

  it("expires sessions by absolute and idle lifetime", () => {
    const now = Date.parse("2026-06-10T00:00:00.000Z");
    expect(sessionExpiryReason({
      issuedAt: new Date(now - 60_000).toISOString(),
      lastUsedAt: new Date(now - 60_000).toISOString(),
    }, now)).toBeNull();
    expect(sessionExpiryReason({
      issuedAt: new Date(now - SESSION_ABSOLUTE_MS - 1).toISOString(),
      lastUsedAt: new Date(now - 60_000).toISOString(),
    }, now)).toBe("absolute");
    expect(sessionExpiryReason({
      issuedAt: new Date(now - 60_000).toISOString(),
      lastUsedAt: new Date(now - SESSION_IDLE_TIMEOUT_MS - 1).toISOString(),
    }, now)).toBe("idle");
  });

  it("uses shorter expiry windows for platform-admin sessions", () => {
    const now = Date.parse("2026-06-10T00:00:00.000Z");
    expect(sessionExpiryReason({
      role: "admin",
      accessMode: "credentialed",
      issuedAt: new Date(now - ADMIN_SESSION_ABSOLUTE_MS - 1).toISOString(),
      lastUsedAt: new Date(now - 60_000).toISOString(),
    }, now)).toBe("absolute");
    expect(sessionExpiryReason({
      role: "admin",
      accessMode: "credentialed",
      issuedAt: new Date(now - 60_000).toISOString(),
      lastUsedAt: new Date(now - ADMIN_SESSION_IDLE_TIMEOUT_MS - 1).toISOString(),
    }, now)).toBe("idle");
    expect(sessionExpiryReason({
      role: "reviewer",
      accessMode: "guest",
      issuedAt: new Date(now - 60_000).toISOString(),
      lastUsedAt: new Date(now - ADMIN_SESSION_IDLE_TIMEOUT_MS - 1).toISOString(),
    }, now)).toBeNull();
  });

  it("blocks analyst chatbot software-development requests while allowing hunt artifacts", async () => {
    expect(isChatbotCodeDevelopmentRequest("Please patch OptraSight to add a new API route.")).toBe(true);
    expect(isChatbotCodeDevelopmentRequest("Run npm build and fix the TypeScript errors in the platform.")).toBe(true);
    expect(isChatbotCodeDevelopmentRequest("Write a Python script for this app and commit it.")).toBe(true);

    expect(isChatbotCodeDevelopmentRequest("Generate a Sigma detection rule for this ransomware behavior.")).toBe(false);
    expect(isChatbotCodeDevelopmentRequest("Create a KQL hunt query for suspicious PowerShell execution.")).toBe(false);

    const result = await runChatConverse({
      resolveAiProvider: () => {
        throw new Error("policy-blocked requests must not reach the AI provider");
      },
    }, {
      tenantId: "tenant-1",
      messages: [{ role: "user", content: "Please modify the OptraSight chatbot code and patch the route." }],
    });

    expect(result.providerLabel).toBe("OptraSight policy");
    expect(result.reply).toContain("cannot help change");
  });
});
