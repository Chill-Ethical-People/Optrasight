# Client Brief AI assets

The canonical knowledge source is [`docs/WEEKLY_THREAT_INTELLIGENCE_DIGEST_GUIDE.md`](../../docs/WEEKLY_THREAT_INTELLIGENCE_DIGEST_GUIDE.md). Regenerate derived RAG artifacts whenever that guide changes.

## Deliverables

- **Agent Skill:** [`skills/client-brief-drafting/`](../../skills/client-brief-drafting/) provides a portable Codex-style Skill with a bundled reference copy.
- **Gemini Gem:** [`gemini/gem-configuration.md`](gemini/gem-configuration.md) contains the Gem name, description, complete instructions, knowledge-file selection, and starters.
- **RAG pack:** [`rag/client-brief-guide.jsonl`](rag/client-brief-guide.jsonl) is a provider-neutral chunk corpus with traceable metadata. [`rag/manifest.json`](rag/manifest.json) records the source hash and retrieval defaults.

## Regenerate the RAG pack

```bash
npm run rag:client-brief
```

Use [`rag/retrieval-policy.md`](rag/retrieval-policy.md) as the query and answer policy for a vector store or managed retrieval service. Generate embeddings with the provider approved for the deployment; embeddings are deliberately not committed.
