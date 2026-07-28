import { describe, expect, it } from "vitest";

import { resolveAiPromptFromConfig, type PromptRegistryConfig } from "../server/promptRegistry";

describe("prompt registry", () => {
  it("applies global and task tuning in provider/model precedence order", () => {
    const config: PromptRegistryConfig = {
      schemaVersion: 1,
      global: {
        default: { mode: "append", text: "global" },
        providers: { deepseek: { mode: "append", text: "provider" } },
      },
      tasks: {
        client_digest: {
          default: { mode: "append", text: "task" },
          models: { "deepseek/deepseek-chat": { mode: "append", text: "model" } },
        },
      },
    };

    expect(
      resolveAiPromptFromConfig(config, "client_digest", { provider: "deepseek", model: "deepseek-chat" }, "built-in"),
    ).toBe("built-in\n\nglobal\n\nprovider\n\ntask\n\nmodel");
  });

  it("allows an exact model override to replace earlier layers", () => {
    const config: PromptRegistryConfig = {
      schemaVersion: 1,
      global: { default: { mode: "append", text: "global" } },
      tasks: {
        osint_chat: {
          models: { "openai/gpt-4.1": { mode: "replace", text: "complete replacement" } },
        },
      },
    };

    expect(
      resolveAiPromptFromConfig(config, "osint_chat", { provider: "openai", model: "gpt-4.1" }, "built-in"),
    ).toBe("complete replacement");
  });
});
