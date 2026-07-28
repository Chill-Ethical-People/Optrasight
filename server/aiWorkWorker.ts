import { storage } from "./storage";
import { runChatDeepDive } from "./osintChat";

type DetectionRulePayload = {
  findingIds: string[];
  languages: string[];
  title?: string;
  actor: string;
};

type ThreatActorPayload = {
  actorId: string;
  force: boolean;
  providerId?: string | null;
  actor: string;
};

type DeepDivePayload = {
  findingIds: string[];
};

type AiWorkPayload = DetectionRulePayload | ThreatActorPayload | DeepDivePayload;

async function runWork(jobId: string, tenantId: string, kind: string, payload: AiWorkPayload) {
  if (kind === "detection_rule_generation") {
    const input = payload as DetectionRulePayload;
    storage.setAiJobProgress(jobId, 10);
    const result = await storage.generateHuntQueries(tenantId, {
      findingIds: input.findingIds,
      languages: input.languages,
      title: input.title,
      createdBy: input.actor,
    });
    if (result?.id) {
      storage.updateAiJobTarget(jobId, {
        targetLabel: result.title,
        targetUrl: result.detectionRuleId
          ? `/#/detection-rules?rule=${encodeURIComponent(result.detectionRuleId)}`
          : "/#/detection-rules",
      });
    }
    return { result, providerLabel: result.aiProviderLabel ?? null };
  }

  if (kind === "threat_actor_enrichment") {
    const input = payload as ThreatActorPayload;
    storage.setAiJobProgress(jobId, 8);
    const result = storage.enrichThreatActor(tenantId, input.actorId, {
      force: input.force,
      actor: input.actor,
      providerId: input.providerId ?? null,
    });
    storage.setAiJobProgress(jobId, 92);
    return { result, providerLabel: result.aiProviderLabel ?? null };
  }

  if (kind === "chat_deep_dive") {
    const input = payload as DeepDivePayload;
    storage.setAiJobProgress(jobId, 15);
    if (!storage.resolveAiProvider(tenantId, "osint_analysis")) {
      throw new Error(
        "No live-tested AI provider is configured for CIRT deep dive. Open AI Setup, enable a provider, and assign it to OSINT analysis.",
      );
    }
    storage.setAiJobProgress(jobId, 35);
    const result = await runChatDeepDive(storage, { tenantId, findingIds: input.findingIds });
    storage.setAiJobProgress(jobId, 90);
    return { result, providerLabel: result.providerLabel ?? null };
  }

  throw new Error(`Unsupported AI worker kind: ${kind}`);
}

async function main() {
  const [jobId, tenantId, kind, encodedPayload] = process.argv.slice(2);
  if (!jobId || !tenantId || !kind || !encodedPayload) {
    throw new Error("AI work worker requires jobId, tenantId, kind, and payload.");
  }
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as AiWorkPayload;
  storage.markAiJobRunning(jobId);
  const heartbeat = setInterval(() => {
    try {
      storage.setAiJobHeartbeat(jobId);
    } catch {
      // The next heartbeat or terminal write will surface a persistent DB issue.
    }
  }, 30_000);
  try {
    const { result, providerLabel } = await runWork(jobId, tenantId, kind, payload);
    storage.completeAiJob(jobId, result, providerLabel);
  } catch (error) {
    storage.failAiJob(jobId, error);
    throw error;
  } finally {
    clearInterval(heartbeat);
  }
}

main().then(
  () => process.exit(0),
  (error) => {
    console.error("[ai-work-worker]", error);
    process.exit(1);
  },
);
