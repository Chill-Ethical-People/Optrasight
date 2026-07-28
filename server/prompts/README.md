# AI prompt tuning registry

`ai-prompts.json` is the central, version-controlled tuning layer for every active OptraSight AI job. The full defensive and output-schema baselines stay next to their validators in code; this registry lets operators tune those baselines without editing each job implementation.

Prompt resolution is deterministic:

1. built-in task prompt;
2. global default, provider, then exact-model tuning;
3. task default, provider, then exact-model tuning.

Use `append` for normal tuning. Use `replace` only when the replacement contains the complete security, language, evidence, and JSON-output contract expected by the task validator.

Provider keys use the AI Setup provider id, such as `deepseek`, `openai`, or `gemini`. Model keys can be either the model name (`deepseek-chat`) or the exact `provider/model` form (`deepseek/deepseek-chat`). Exact provider/model keys take precedence.

Example:

```json
{
  "tasks": {
    "client_digest": {
      "providers": {
        "deepseek": {
          "mode": "append",
          "text": "Keep the executive summary under 120 words."
        }
      },
      "models": {
        "openai/gpt-4.1": {
          "mode": "append",
          "text": "Prefer short, explicit evidence statements."
        }
      }
    }
  }
}
```

Restart the OptraSight backend after changing the JSON so the bundled production process loads the new registry.
