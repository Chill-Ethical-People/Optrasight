import { storage } from "./storage";
import { runChatTriage, type ChatRangeKey } from "./osintChat";

type WorkerPayload = {
  range: ChatRangeKey;
  findingIds?: string[];
  analysisMode: "cirt" | "client_impact";
  clientIds: string[];
  actor: string;
  digestCadence?: "daily" | "weekly" | "biweekly" | "monthly";
};

async function main() {
  const [jobId, tenantId, encodedPayload] = process.argv.slice(2);
  if (!jobId || !tenantId || !encodedPayload) {
    throw new Error("Chat triage worker requires jobId, tenantId, and payload.");
  }
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as WorkerPayload;
  storage.markAiJobRunning(jobId);
  storage.setAiJobProgress(jobId, 15);
  try {
    if (!storage.resolveAiProvider(tenantId, "osint_overview")) {
      throw new Error(
        "No live-tested AI provider is configured for CIRT triage. Open AI Setup, enable a provider, and assign it to OSINT overview.",
      );
    }
    storage.setAiJobProgress(jobId, 30);
    const result = await runChatTriage(storage, {
      tenantId,
      range: payload.range,
      findingIds: payload.findingIds,
      analysisMode: payload.analysisMode,
      clientIds: payload.clientIds,
    });
    const drafts: Array<{
      clientId: string;
      status: "created" | "skipped" | "failed";
      digestId?: string;
      message?: string;
    }> = [];
    if (payload.analysisMode === "client_impact") {
      storage.setAiJobProgress(jobId, 72);
      for (const selection of result.clientSelections ?? []) {
        if (selection.focusedFindingIds.length + selection.generalFindingIds.length === 0) {
          drafts.push({
            clientId: selection.clientId,
            status: "skipped",
            message: "No material intelligence was selected for this client.",
          });
          continue;
        }
        try {
          const profile = storage.getClientProfile(tenantId, selection.clientId);
          const cadence = payload.digestCadence ?? (
            payload.range === "1d"
              ? "daily"
              : payload.range === "7d"
                ? "weekly"
                : payload.range === "2w"
                  ? "biweekly"
                : payload.range === "1m"
                  ? "monthly"
                  : profile?.digestCadence
          );
          const digest = await storage.generateClientDigest(tenantId, selection.clientId, {
            cadence,
            assessmentSelection: {
              focusedFindingIds: selection.focusedFindingIds,
              generalFindingIds: selection.generalFindingIds,
              sourceJobId: jobId,
            },
            actor: payload.actor,
          });
          drafts.push({ clientId: selection.clientId, status: "created", digestId: digest.id });
        } catch (error) {
          drafts.push({
            clientId: selection.clientId,
            status: "failed",
            message: error instanceof Error ? error.message : "Draft generation failed.",
          });
        }
      }
    }
    storage.setAiJobProgress(jobId, 95);
    storage.completeAiJob(
      jobId,
      { ...result, ...(payload.analysisMode === "client_impact" ? { drafts } : {}) },
      result.providerLabel,
    );
  } catch (error) {
    storage.failAiJob(jobId, error);
    throw error;
  }
}

main().then(
  () => process.exit(0),
  (error) => {
    console.error("[chat-triage-worker]", error);
    process.exit(1);
  },
);
