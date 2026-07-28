---
name: client-brief-drafting
description: Draft, revise, adapt, or quality-check evidence-led cyber threat intelligence Client Briefs, weekly digests, MSS/MDR/IR notifications, CTI subscriber reporting, advisory snapshots, and OptraSight DOCX or email templates. Use when an AI agent must turn supplied reporting, telemetry, indicators, client scope, and analyst assessments into a defensible client-facing brief without inventing exposure, attribution, or defensive coverage.
---

# Client Brief Drafting

Produce decision-focused threat-intelligence communications while preserving evidence, service scope, confidence, and human approval.

## Required reference

Read [references/client-brief-guide.md](references/client-brief-guide.md) completely before drafting or reviewing a brief. Use its audience positioning, terminology, reusable language, templates, claims guardrails, and pre-distribution checklist.

## Workflow

1. Identify the audience and matching scope:
   - `cti_subscription`: emphasise campaign context, actor behaviour, confidence, indicators, intelligence gaps, and outlook. Do not imply direct exposure from strategic relevance.
   - `managed_security`: emphasise in-scope telemetry, plausible or confirmed exposure, detection coverage, hunting, containment, owners, and deadlines.
   - `hybrid`: separate strategic intelligence from environment-specific operational findings and actions.
   - `advisory`: demonstrate tailored CTI value without implying an existing monitored environment.
2. Inventory the supplied facts. Separate direct observations, third-party reporting, analytical assessments, client-profile matches, and unknowns.
3. Reject unsupported conclusions. Never invent telemetry results, exposure, attribution, indicator validation, detection coverage, actions completed, or source links.
4. Rank material by client relevance, evidence strength, impact, urgency, indicator quality, and service scope. Keep strategic-only items out of operational-action sections unless they create a defensible decision.
5. Draft in plain English. For every priority item, state what happened, why it matters to this client, confidence, evidence limits, and a practical action with an owner or time horizon when supported.
6. Preserve source traceability. Provide a deduplicated source register and associate material claims with supplied sources. Mark missing evidence as an intelligence gap.
7. Apply the quality gate before returning a distributable draft.

## Default output

Return these sections unless the user supplies another approved structure:

1. Subject
2. Executive assessment
3. Priority intelligence
4. Client relevance and exposure status
5. Indicators and detection opportunities
6. Recommended actions
7. Outlook
8. Sources
9. Analyst review notes and unresolved gaps

Use `Observed`, `Reported`, `Assessed`, and `Unknown` precisely. Qualify confidence as High, Moderate, or Low and explain material limitations.

## OptraSight template contract

When creating or reviewing an OptraSight Word/email template:

- Keep `{{client_name}}` in the subject.
- Keep `{{executive_summary}}` and `{{sources}}` in the body.
- Put generated block placeholders on their own lines.
- Use only placeholders listed in the reference guide.
- Treat square-bracket placeholders in example prose as drafting notation, not template-engine tokens.

## Distribution guardrails

- Produce a draft only; never claim it was approved or sent.
- Require analyst review before distribution.
- Apply the supplied TLP marking and sharing restrictions.
- Do not recommend automatic blocking for shared or low-confidence infrastructure.
- Do not state that no threat exists. State only that no related activity was identified within the available scope when evidence supports that statement.
- Do not state that a client is unaffected when exposure could not be determined.
- Do not expose secrets, private client identifiers, or data outside the requested audience.

## Final quality gate

Confirm that every placeholder is resolved, dates and counts are supported, priority items explain relevance, confidence matches evidence, attribution is qualified, indicator handling is proportionate, actions are practical, source links are present, TLP is correct, and unsupported claims have been removed. If any check fails, label the output `DRAFT — ANALYST REVIEW REQUIRED` and list the blocking gaps.
