export const CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS = [
  {
    token: "{{client_name}}",
    label: "Client name",
    placement: "Inline",
    required: true,
    description: "The selected client profile name.",
  },
  {
    token: "{{cadence}}",
    label: "Cadence",
    placement: "Inline",
    required: false,
    description: "Daily, Weekly, Bi-weekly, or Monthly.",
  },
  {
    token: "{{period_start}}",
    label: "Period start",
    placement: "Inline",
    required: false,
    description: "Start date of the intelligence window.",
  },
  {
    token: "{{period_end}}",
    label: "Period end",
    placement: "Inline",
    required: false,
    description: "End date of the intelligence window.",
  },
  {
    token: "{{overall_risk}}",
    label: "Overall risk",
    placement: "Inline",
    required: false,
    description: "Aggregated client risk rating derived from included intelligence.",
  },
  {
    token: "{{risk_trend}}",
    label: "Risk trend",
    placement: "Inline",
    required: false,
    description: "Increasing, Stable, or Decreasing when evidence supports a trend.",
  },
  {
    token: "{{executive_summary}}",
    label: "Executive summary",
    placement: "Own line",
    required: true,
    description: "A short decision-focused summary for client leadership.",
  },
  {
    token: "{{tier_1}}",
    label: "Critical intelligence",
    placement: "Own line",
    required: false,
    description: "Critical-severity intelligence with assessment, recommendation, ownership, timing, and reference.",
  },
  {
    token: "{{tier_2}}",
    label: "High intelligence",
    placement: "Own line",
    required: false,
    description: "High-severity intelligence with assessment, recommendation, ownership, timing, and reference.",
  },
  {
    token: "{{tier_3}}",
    label: "Medium intelligence",
    placement: "Own line",
    required: false,
    description: "Medium-severity intelligence with assessment, recommendation, ownership, timing, and reference.",
  },
  {
    token: "{{fyi}}",
    label: "Low and FYI",
    placement: "Own line",
    required: false,
    description:
      "Low-severity or broader situational-awareness intelligence, clearly separated from confirmed client exposure.",
  },
  {
    token: "{{recommended_actions}}",
    label: "Action summary",
    placement: "Own line",
    required: false,
    description: "Prioritized actions with suggested owner and target timing.",
  },
  {
    token: "{{indicator_summary}}",
    label: "Indicator summary",
    placement: "Own line",
    required: false,
    description: "Shareable IOC counts, CVEs, and detection-support availability.",
  },
  {
    token: "{{sources}}",
    label: "Sources",
    placement: "Own line",
    required: true,
    description: "Deduplicated Markdown links to supplied source material.",
  },
] as const;

export const CLIENT_DIGEST_TEMPLATE_TOKENS = CLIENT_DIGEST_TEMPLATE_PLACEHOLDERS.map((item) => item.token);

export const CLIENT_DIGEST_REQUIRED_SUBJECT_TOKENS = ["{{client_name}}"] as const;
export const CLIENT_DIGEST_REQUIRED_BODY_TOKENS = ["{{executive_summary}}", "{{sources}}"] as const;

export function missingRequiredClientDigestPlaceholders(subjectTemplate: string, bodyTemplate: string): string[] {
  return [
    ...CLIENT_DIGEST_REQUIRED_SUBJECT_TOKENS.filter((token) => !subjectTemplate.includes(token)),
    ...CLIENT_DIGEST_REQUIRED_BODY_TOKENS.filter((token) => !bodyTemplate.includes(token)),
  ];
}

export const DEFAULT_CLIENT_DIGEST_SUBJECT_TEMPLATE =
  "[OptraSight Threat Intelligence] {{client_name}} | {{cadence}} Risk Brief | {{period_end}}";

export const LEGACY_CLIENT_DIGEST_BODY_TEMPLATE = `Hello {{client_name}} Security Team,

## Executive Summary

**Overall risk:** {{overall_risk}}<br>
**Risk trend:** {{risk_trend}}<br>
**Reporting period:** {{period_start}} to {{period_end}}

{{executive_summary}}

## Tier 1 - Action Required

{{tier_1}}

## Tier 2 - Priority Review

{{tier_2}}

## Tier 3 - Monitor and Plan

{{tier_3}}

## FYI - Situational Awareness

{{fyi}}

## Recommended Action Summary

{{recommended_actions}}

## Indicators and Detection Support

{{indicator_summary}}

## Sources

{{sources}}

Please contact the threat-intelligence team if you require supporting indicators, detection queries, or additional analysis.

Regards,

OptraSight Threat Intelligence`;

export const DEFAULT_CLIENT_DIGEST_BODY_TEMPLATE = `Hello {{client_name}} Security Team,

## Executive Summary

**Overall risk:** {{overall_risk}}<br>
**Risk trend:** {{risk_trend}}<br>
**Reporting period:** {{period_start}} to {{period_end}}

{{executive_summary}}

## Critical - Immediate Attention

{{tier_1}}

## High - Priority Review

{{tier_2}}

## Medium - Monitor and Plan

{{tier_3}}

## Low / FYI - Situational Awareness

{{fyi}}

## Recommended Action Summary

{{recommended_actions}}

## Indicators and Detection Support

{{indicator_summary}}

## Reference Register

{{sources}}

Please contact the threat-intelligence team if you require supporting indicators, detection queries, or additional analysis.

Regards,

OptraSight Threat Intelligence`;

export function unsupportedClientDigestPlaceholders(value: string): string[] {
  const allowed = new Set<string>(CLIENT_DIGEST_TEMPLATE_TOKENS);
  return Array.from(new Set(value.match(/{{\s*[a-zA-Z0-9_]+\s*}}/g) ?? [])).filter((token) => !allowed.has(token));
}
