import { storage } from "./storage";

async function main() {
  const [jobId, tenantId, encodedPayload] = process.argv.slice(2);
  if (!jobId || !tenantId || !encodedPayload) {
    throw new Error("OSINT analysis worker requires jobId, tenantId, and payload.");
  }
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as {
    ids?: string[];
    onlyUnanalyzed?: boolean;
  };
  storage.markAiJobRunning(jobId);
  try {
    const result = await storage.runOsintAnalysis(tenantId, { ...payload, jobId });
    storage.completeAiJob(jobId, result, result.provider);
  } catch (error) {
    storage.failAiJob(jobId, error);
    throw error;
  }
}

main().then(
  () => process.exit(0),
  (error) => {
    console.error("[osint-analysis-worker]", error);
    process.exit(1);
  },
);
