# Batch Two Design Roadmap

This note separates the current delivery focus from deliberately deferred platform design. It is a product boundary, not a commitment to expose Full Platform modules in the Batch One release line.

## Current phase: Client Profile foundation

The major product focus for this phase is the Client Profile and its analyst workflow:

- support multiple protected clients without requiring tenant switching in Intel Inbox;
- model geographies, industries, technologies, subsidiaries, service coverage, notification recipients, and analyst-defined mapping terms;
- use semantic and evidence-based relevance assessment instead of direct string matching;
- let AI propose client tags and impact assessments while analysts retain the final decision and can revise severity;
- preserve separate global intelligence severity and per-client impact severity;
- turn reviewed client-relevant intelligence into editable, auditable email drafts;
- keep MSS and Individual workspace modes coherent, hiding client-only surfaces in Individual mode;
- record assignment, assessment, approval, editing, and delivery actions in the audit trail.

Threat Actor Profile and Detection Rules work in this phase is limited to usability, traceability, and compatibility improvements needed to support that client workflow.

## Deferred design: intelligence lifecycle

The next phase should formalize the intelligence model before adding more workflow automation:

1. Preserve an immutable source observation containing retrieval time, source identity, source URL, original publication time, raw content hash, and parser version.
2. Resolve observations into a canonical intelligence record with deduplication lineage rather than overwriting source evidence.
3. Store indicators, vulnerabilities, actors, campaigns, TTPs, and affected products as linked entities with confidence, first-seen, last-seen, and expiry fields.
4. Store each client-impact assessment separately from the canonical record, including matched profile factors, contradicting evidence, confidence, analyst decision, and change history.
5. Treat distribution as its own controlled record: audience, TLP, approved content, template version, recipients, delivery status, and the exact evidence included.

This creates a defensible chain from observation to assessment to client communication without confusing global severity with client-specific risk.

## Deferred design: source quality

Source quality should be evaluated by operational reliability and analyst outcomes, using the Full Platform implementation as a reference rather than copying its scoring unchanged.

Recommended dimensions:

- **Retrieval health:** availability, HTTP outcome, latency, authentication state, and consecutive failure count.
- **Parsing health:** parse success, schema completeness, publication-date quality, and content-change detection.
- **Evidence value:** corroboration by independent sources, unique information contribution, usable references, and indicator validity.
- **Analyst outcomes:** accepted, dismissed, escalated, linked to a client, used in a brief, or converted into a detection rule.
- **Freshness and decay:** observed time, confirmed publication time, expiry, and stale-content rate. Inferred dates must not be scored as confirmed publication dates.
- **Scoring confidence:** minimum sample size, source-category baseline, and a visible explanation of why the score changed.

The score must not reward alarmist severity, raw article volume, or IOC quantity. Vendor research, government advisories, social signals, vulnerability feeds, and ransomware victim feeds need different baselines.

## Deferred design: distribution and interoperability

- Add outbound TAXII only after TLP, confidence, indicator expiry, sharing policy, and revocation controls are enforced.
- Add structured approval gates for scheduled daily, weekly, bi-weekly, and monthly client briefs.
- Add feedback loops from delivered briefs and deployed detection rules into source and assessment quality metrics.
- Add retention and legal-hold controls before expanding client communication history.

## Exit criteria for the current phase

The Client Profile phase is complete when an analyst can maintain multiple profiles, receive explainable AI relevance suggestions, correct client tags and severity, approve a client-specific assessment, produce an editable draft, and trace every material decision back to source evidence without switching tenant context.
