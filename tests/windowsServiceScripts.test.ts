import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));

describe("Windows service installer", () => {
  it("keeps the health monitor recurring beyond its first run", () => {
    const installer = readFileSync(`${repoRoot}scripts/install-optrasight-windows.ps1`, "utf8");

    expect(installer).toContain("-RepetitionInterval (New-TimeSpan -Minutes 5)");
    expect(installer).toContain("-RepetitionDuration (New-TimeSpan -Days 3650)");
    expect(installer).toContain('Register-ScheduledTask -TaskName $healthTaskName');
  });
});
