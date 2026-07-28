import { storage } from "./storage";

type ProviderWorkerAction = "test" | "models";

async function main() {
  const [action, tenantId, providerId] = process.argv.slice(2) as [ProviderWorkerAction, string, string];
  if (!action || !tenantId || !providerId) throw new Error("Provider worker requires action, tenant, and provider id.");
  const result =
    action === "test"
      ? storage.testAiProvider(tenantId, providerId)
      : storage.listAiProviderModels(tenantId, providerId);
  await send({ ok: true, result });
}

function send(message: Record<string, unknown>): Promise<void> {
  return new Promise((resolve) => {
    if (!process.send) return resolve();
    process.send(message, undefined, undefined, () => resolve());
  });
}

main().then(
  () => process.exit(0),
  async (error) => {
    await send({ ok: false, error: error instanceof Error ? error.message : String(error) });
    process.exit(1);
  },
);
