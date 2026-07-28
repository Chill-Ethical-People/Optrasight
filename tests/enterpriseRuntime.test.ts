import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("enterprise runtime safeguards", () => {
  it("identifies the Batch Two release in browser and installed-app metadata", () => {
    const html = read("client/index.html");
    const manifest = JSON.parse(read("client/public/site.webmanifest"));
    expect(html).toContain("<title>OptraSight Batch Two | Threat Intelligence Operations</title>");
    expect(html).toContain('name="application-name" content="OptraSight Batch Two"');
    expect(html).not.toContain("OptraSight Batch One");
    expect(manifest.name).toBe("OptraSight Batch Two");
  });

  it("persists the primary workspace database inside the Docker volume", () => {
    const dockerfile = read("Dockerfile");
    expect(dockerfile).toContain("OPTRASIGHT_DB_PATH=/app/data/data.db");
    expect(dockerfile).toContain('VOLUME ["/app/data"]');
  });

  it("isolates provider network probes from the Express process", () => {
    const routes = read("server/routes.ts");
    const worker = read("server/aiProviderWorker.ts");
    expect(routes).toContain('runAiProviderWorker("test"');
    expect(routes).toContain('runAiProviderWorker("models"');
    expect(worker).toContain("storage.listAiProviderModels");
  });

  it.each(["scripts/install-optrasight-linux.sh", "scripts/install-optrasight-macos.sh"])(
    "stages, checks, backs up, and health-checks %s",
    (path) => {
      const script = read(path);
      expect(script).toContain('"$NPM_BIN" run check');
      expect(script).toContain("runtime.tar.gz");
      expect(script).toContain("OPTRASIGHT_STRICT=1");
      expect(script).toContain("/api/v1/health");
      expect(script).toContain("previous installation was restored");
    },
  );
});
