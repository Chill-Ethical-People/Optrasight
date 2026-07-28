import type { AiProvider } from "@shared/schema";

import promptConfig from "./prompts/ai-prompts.json";

export type PromptTune = {
  mode?: "append" | "replace";
  text?: string;
};

export type PromptLayer = {
  default?: PromptTune;
  providers?: Record<string, PromptTune>;
  models?: Record<string, PromptTune>;
};

export type PromptRegistryConfig = {
  schemaVersion: number;
  global?: PromptLayer;
  tasks?: Record<string, PromptLayer>;
};

function applyTune(current: string, tune: PromptTune | undefined): string {
  const text = String(tune?.text ?? "").trim();
  if (!text) return current;
  if (tune?.mode === "replace") return text;
  return `${current.trim()}\n\n${text}`.trim();
}

function applyLayer(
  current: string,
  layer: PromptLayer | undefined,
  provider: Pick<AiProvider, "provider" | "model">,
): string {
  if (!layer) return current;
  let resolved = applyTune(current, layer.default);
  resolved = applyTune(resolved, layer.providers?.[provider.provider]);
  const exactModelKey = `${provider.provider}/${provider.model}`;
  resolved = applyTune(resolved, layer.models?.[exactModelKey] ?? layer.models?.[provider.model]);
  return resolved;
}

export function resolveAiPromptFromConfig(
  config: PromptRegistryConfig,
  task: string,
  provider: Pick<AiProvider, "provider" | "model">,
  builtInPrompt: string,
): string {
  let resolved = applyLayer(builtInPrompt, config.global, provider);
  resolved = applyLayer(resolved, config.tasks?.[task], provider);
  return resolved;
}

/**
 * Apply centrally managed prompt tuning to a built-in task prompt.
 * Resolution order is deterministic: built-in -> global -> task, and within
 * each layer default -> provider -> exact model. Later `replace` entries take
 * ownership of the complete prompt; `append` is the safer normal choice.
 */
export function resolveAiPrompt(
  task: string,
  provider: Pick<AiProvider, "provider" | "model">,
  builtInPrompt: string,
): string {
  return resolveAiPromptFromConfig(promptConfig as PromptRegistryConfig, task, provider, builtInPrompt);
}
