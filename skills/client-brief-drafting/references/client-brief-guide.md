# Weekly Threat Intelligence Digest Drafting Guide

## Purpose

This guide provides reusable vocabulary, phrases, and email templates for drafting weekly threat intelligence digests for three audiences:

1. Cyber Threat Intelligence (CTI) service subscribers
2. Managed Detection and Response (MDR), Managed Detection and Defence (MDD), or Incident Response (IR) clients
3. General cybersecurity clients and prospects receiving a demonstration of CTI capability

Use only information supported by current reporting, available telemetry, or documented analysis. Replace every bracketed placeholder before distribution.

## Placeholder convention

### OptraSight DOCX template contract

OptraSight Word templates use double-brace placeholders. Three placeholders are required so every Client Brief remains identifiable, decision-focused, and evidence-linked:

| Placeholder             | Required location | Purpose                                       |
| ----------------------- | ----------------- | --------------------------------------------- |
| `{{client_name}}`       | Subject           | Identifies the intended Client Profile.       |
| `{{executive_summary}}` | Body              | Provides the AI-drafted decision summary.     |
| `{{sources}}`           | Body              | Preserves the deduplicated evidence register. |

Optional placeholders are `{{cadence}}`, `{{period_start}}`, `{{period_end}}`, `{{overall_risk}}`, `{{risk_trend}}`, `{{tier_1}}`, `{{tier_2}}`, `{{tier_3}}`, `{{fyi}}`, `{{recommended_actions}}`, and `{{indicator_summary}}`.

The safest editing workflow is: download the current Word template from Client Profiles → Client emails, edit the wording and layout without deleting the three required placeholders, then upload the `.docx` on the same screen. Word may split a placeholder across internal runs; OptraSight reconstructs those runs during validation.

The bracketed placeholders below are drafting-guide notation only; they are not processed by the OptraSight template engine.

- `[Client Name]`: recipient organisation or team
- `[Reporting Period]`: start and end dates covered by the digest
- `[Threat/Campaign]`: named actor, malware family, campaign, or activity cluster
- `[Technology]`: affected product, service, or platform
- `[Industry/Region]`: relevant sector or geography
- `[Confidence]`: High, Moderate, or Low
- `[Priority]`: Immediate, Elevated, or Routine
- `[TLP]`: applicable Traffic Light Protocol classification
- `[Number]`: validated count taken from the reporting dataset

## Drafting principles

- Separate confirmed observations from analytical assessments and third-party reporting.
- State why an item is relevant to the recipient, not merely what happened.
- Assign confidence according to the strength and consistency of the supporting evidence.
- Assess indicators for freshness, source fidelity, context, and false-positive potential.
- Do not recommend automatic blocking of low-confidence indicators or shared infrastructure.
- Distinguish client telemetry from the broader threat landscape.
- Never claim that a prospect is unaffected when its environment is not monitored.
- Use the applicable TLP classification and respect all source-sharing restrictions.
- End each significant finding with a practical action, owner, or monitoring decision.
- Use plain English for executive readers and add technical detail only where it supports a decision.

## Audience positioning

### CTI service subscriber

Emphasise analytical depth, campaign context, attribution, confidence, intelligence gaps, indicators, and the outlook.

OptraSight matching scope: `cti_subscription`. A direct technology match is not mandatory when actor, campaign, victimology, sector, geography, IoC/TTP utility, or strategic outlook provides defensible intelligence value. Do not convert strategic relevance into an unsupported exposure claim.

### MDR, MDD, or IR client

Emphasise environment status, telemetry correlation, detection coverage, threat-hunting results, containment, and required client actions.

OptraSight matching scope: `managed_security`. Prioritise plausible or confirmed technology exposure, detection and telemetry applicability, indicator fitness, patching, hunting, and containment. Strategic-only items normally remain general threat watch.

### General cybersecurity client or prospect

Demonstrate how the CTI service turns high-volume reporting into tailored and actionable intelligence. Do not present the digest as a generic cyber-news newsletter, and do not imply that the recipient's environment is already monitored.

OptraSight matching scope: `advisory`. Profiles combining TI with MSS, MDR, or CIR use the `hybrid` scope and keep strategic intelligence separate from environment-specific operational action.

## Bulk Client Profile creation

Client Profiles → Bulk import accepts a CSV of up to 100 rows. Download the in-product CSV template and use `|` within a cell for multiple services, geographies, industries, technologies, mapping terms, or notification emails. Existing taxonomy labels and aliases resolve to canonical IDs. Keep “create unknown taxonomy labels” disabled for typo detection, or enable it when the CSV intentionally introduces reviewed custom scope labels.

# Word bank

## Intelligence significance

- Priority intelligence
- Material development
- Notable activity
- Emerging threat
- Heightened activity
- Significant campaign
- Relevant exposure
- Developing situation
- Credible threat
- Persistent threat
- Sector-specific risk
- Geographic relevance
- Operational significance
- Strategic implication
- Immediate concern
- Longer-term concern
- Intelligence priority
- Collection priority

## Analytical verbs

- Assessed
- Analysed
- Correlated
- Contextualised
- Enriched
- Validated
- Prioritised
- Identified
- Observed
- Detected
- Tracked
- Attributed
- Linked
- Mapped
- Triaged
- Deduplicated
- Investigated
- Evaluated
- Substantiated
- Disputed
- Forecast
- Monitored

### Usage distinctions

- Use **observed** only when activity was directly seen in telemetry or reliable first-hand reporting.
- Use **assessed** for an analytical judgement.
- Use **reported** when describing information supplied by another source.
- Use **attributed** only when sufficient evidence supports the attribution.
- Use **identified** for a finding without implying that maliciousness or attribution is confirmed.

## Confidence and evidence

### High confidence

- We assess with high confidence
- Multiple independent sources corroborate
- Supported by consistent technical evidence
- Directly observed in the available telemetry
- Strongly associated with
- The available evidence indicates
- Technical and contextual evidence consistently supports

### Moderate confidence

- We assess with moderate confidence
- Available reporting suggests
- Several indicators are consistent with
- Probably associated with
- The evidence supports, but does not confirm
- Attribution remains plausible
- The observed pattern broadly aligns with

### Low or developing confidence

- We assess with low confidence
- Preliminary reporting indicates
- The relationship remains unconfirmed
- Available evidence is limited
- Further corroboration is required
- Attribution remains tentative
- This assessment may change as additional information becomes available

## Threat activity and campaigns

### Nouns

- Threat actor
- Adversary
- Intrusion set
- Campaign
- Operation
- Malicious infrastructure
- Initial-access activity
- Credential-harvesting operation
- Phishing campaign
- Exploitation activity
- Malware deployment
- Ransomware operation
- Data-extortion activity
- Supply-chain compromise
- Business email compromise
- Account takeover
- Persistence mechanism
- Command-and-control activity
- Data staging
- Data exfiltration
- Lateral movement
- Defence evasion
- Operational technology targeting

### Activity verbs

- Targeting
- Exploiting
- Weaponising
- Impersonating
- Harvesting
- Compromising
- Deploying
- Establishing persistence
- Escalating privileges
- Evading detection
- Exfiltrating
- Disrupting
- Extorting
- Monetising access

## Client relevance

- Relevant to your technology footprint
- Applicable to your operating environment
- Aligned with your sector threat profile
- Relevant to your geographic presence
- Potentially affecting internet-facing assets
- Of particular relevance to organisations using `[Technology]`
- Consistent with threats facing the `[Industry]` sector
- Relevant to your third-party ecosystem
- Applicable to privileged-access workflows
- Material to your business operations
- Warrants review by the `[Security/IT/Risk]` team
- No direct exposure has been identified within the available scope
- Exposure could not be determined from the information currently available

## Risk and impact

### Risk descriptors

- Low
- Moderate
- Elevated
- High
- Critical
- Localised
- Widespread
- Opportunistic
- Targeted
- Persistent
- Time-sensitive
- Potentially material
- Operationally disruptive

### Potential consequences

- Credential compromise
- Unauthorised access
- Service disruption
- Data exposure
- Financial loss
- Fraudulent transactions
- Reputational damage
- Regulatory exposure
- Loss of operational resilience
- Third-party compromise
- Intellectual-property theft
- Business interruption

## Indicators and feed quality

- Validated indicators
- Enriched indicators
- High-confidence indicators
- Detection-relevant observables
- Contextual indicators
- Behavioural indicators
- Technical artefacts
- Indicator package
- Machine-readable intelligence
- Source fidelity
- Indicator freshness
- Indicator ageing
- Time to live
- False-positive potential
- Shared infrastructure
- Deduplicated dataset
- Cross-source correlation
- Passive DNS enrichment
- Infrastructure overlap
- Historical association
- Detection-only indicator
- Blocking candidate

## Recommended-action verbs

- Review
- Validate
- Prioritise
- Patch
- Mitigate
- Restrict
- Monitor
- Investigate
- Hunt
- Correlate
- Isolate
- Contain
- Block
- Detect
- Enrich
- Escalate
- Verify
- Harden
- Disable
- Rotate
- Revoke
- Baseline
- Tune
- Deploy
- Communicate

## Outlook and forecasting

- We anticipate continued activity
- Further exploitation is likely
- Targeting may expand to
- Activity is expected to remain elevated
- The campaign will probably continue
- We are monitoring for indications of
- Near-term risk is expected to increase
- No material escalation is currently anticipated
- The situation remains fluid
- The assessment will be updated as new intelligence becomes available
- An out-of-cycle notification will be issued if the risk materially changes

# Reusable phrase bank

## Opening phrases

- Please find your Weekly Threat Intelligence Digest for `[Reporting Period]`.
- This edition highlights the developments assessed as most relevant to your organisation's sector, geography, and technology footprint.
- This week's digest provides an intelligence-led view of priority threats, potential exposure, and recommended defensive actions.
- The reporting period was characterised by `[heightened/stable/decreasing]` activity affecting `[Industry/Technology/Region]`.
- We have prioritised the following developments based on their relevance, potential impact, and the strength of the available evidence.
- This sample briefing demonstrates how multi-source reporting is transformed into contextualised and actionable cyber threat intelligence.

## Executive-summary phrases

- We assess the overall threat level for this reporting period as `[Risk Level]`.
- The most material development this week was `[Threat/Campaign]`.
- No single development materially changed the overall threat picture; however, continued monitoring of `[Issue]` is warranted.
- Activity remained broadly consistent with patterns observed during the previous reporting period.
- The principal risk arises from `[Threat]`, particularly for organisations using `[Technology]`.
- The intelligence picture indicates an increased likelihood of `[Outcome]` over the near term.
- The available evidence does not currently indicate a material escalation in risk.
- Although exploitation remains limited, the potential operational impact warrants early mitigation.

## Threat-actor and campaign phrases

- `[Threat Actor]` continued to target organisations in the `[Industry/Region]` sector using `[Technique]`.
- The activity is consistent with the actor's previously documented focus on `[Objective]`.
- The campaign combines `[Initial Access Method]` with `[Malware/Tool]` to establish access and support follow-on activity.
- Observed infrastructure overlaps with assets previously associated with `[Threat/Campaign]`.
- The available evidence supports a possible relationship with `[Actor]`, although attribution remains unconfirmed.
- We assess that the actor's likely objective is `[Espionage/Financial Gain/Disruption/Access Brokerage]`.
- The campaign appears opportunistic in scale but selective in its follow-on targeting.
- The actor has demonstrated the capability and intent to exploit `[Technology/Exposure]`.

## Vulnerability phrases

- `[Vulnerability]` affects `[Product/Versions]` and may permit `[Impact]` under `[Conditions]`.
- Public proof-of-concept code has increased the likelihood of opportunistic exploitation.
- Exploitation has been reported in the wild, making remediation time-sensitive.
- No confirmed exploitation has been identified in the information currently available.
- Internet-facing instances should be identified and prioritised for remediation.
- Where immediate patching is not possible, apply vendor-recommended mitigations and increase monitoring.
- Successful exploitation could enable unauthorised access, credential theft, or lateral movement.
- The vulnerability is relevant because `[Technology]` is commonly deployed within `[Sector/Business Function]`.

## Client-relevance phrases

- This development is relevant to your organisation because `[Reason]`.
- The affected technology appears within the service scope and warrants exposure validation.
- The campaign's targeting profile overlaps with your sector and geographic presence.
- The activity may affect organisations with similar technology and third-party dependencies.
- Direct applicability depends on the presence and configuration of `[Technology]`.
- This development has limited direct relevance to your current technology footprint but remains useful for situational awareness.
- Exposure could not be determined from the data currently available.
- No related activity was identified within the monitored scope during the reporting period.
- This statement applies only to the telemetry and services currently in scope.

## Indicator phrases

- The associated indicators have been deduplicated, enriched, and assessed for freshness and confidence.
- Indicators were correlated across multiple sources to reduce duplication and improve contextual value.
- High-confidence indicators are suitable for detection, enrichment, and targeted investigation.
- Low-confidence indicators should be monitored and correlated with additional evidence before action is taken.
- Indicators associated with shared hosting or content-delivery infrastructure should not be blocked without contextual validation.
- The indicator package contains `[Number]` domains, `[Number]` IP addresses, `[Number]` URLs, and `[Number]` file hashes.
- Behavioural detections are likely to remain useful after short-lived infrastructure indicators expire.
- Indicator age and infrastructure reuse should be considered when interpreting any matches.

## Detection and hunting phrases

- Review available telemetry for evidence of `[Technique/Indicator/Behaviour]`.
- Prioritise searches for the behavioural sequence rather than relying exclusively on atomic indicators.
- Detection coverage is available for `[Technique]`; additional tuning is recommended for `[Gap]`.
- A targeted threat hunt found no related activity within the available telemetry.
- The hunt identified `[Finding]`, which remains under investigation.
- Correlate authentication, endpoint, network, and cloud telemetry to identify possible follow-on activity.
- Monitor for anomalous execution of `[Tool/Process]` on internet-facing or privileged systems.
- Validate that alerts for `[Technique]` are enabled, appropriately prioritised, and routed to the responsible team.

## Recommended-action phrases

- Immediate action is recommended due to active exploitation and the potential for material impact.
- Prioritise this action within 24 hours.
- Address this item during the next scheduled patching cycle.
- Detection and monitoring are recommended while the assessment remains under development.
- Validate exposure before implementing broad blocking controls.
- Apply vendor guidance and verify the effectiveness of the mitigation.
- Review privileged accounts and rotate credentials where compromise is suspected.
- No immediate action is required beyond continued monitoring.
- Escalate any related findings through the established incident-response process.
- Assign an owner and target completion date for each outstanding action.

## No-material-activity phrases

- No material threat activity was identified during the reporting period.
- No related indicators were identified within the available telemetry.
- No confirmed exploitation affecting the monitored environment was observed.
- The absence of observed activity should not be interpreted as proof of absence outside the monitored scope.
- The threat remains relevant for awareness, although no immediate response action is required.
- Monitoring will continue, and any material change will be communicated outside the normal reporting cycle.

## Outlook phrases

- We anticipate continued targeting of `[Industry/Technology]` over the next `[Period]`.
- Further exploitation is likely as technical details and proof-of-concept code become more widely available.
- Near-term activity will probably remain opportunistic, with targeted follow-on operations against high-value victims.
- We are monitoring for changes in infrastructure, tooling, targeting, and exploitation status.
- No material escalation is currently anticipated, but the situation remains fluid.
- We will update this assessment as new and credible intelligence becomes available.
- An out-of-cycle alert will be issued if the threat level or required response materially changes.

## Closing phrases

- The detailed report and applicable indicator package are `[attached/available through the client portal]`.
- Please handle this information in accordance with `[TLP]`.
- Contact the CTI team if you require additional context, a tailored assessment, or machine-readable indicators.
- Contact the SOC or IR team immediately if related activity is identified.
- We would be pleased to provide a tailored briefing based on your sector, technology footprint, and priority intelligence requirements.
- Please let us know if you would like a deeper assessment of any item covered in this digest.

## CTI capability-demonstration phrases

- We transform high-volume threat reporting into prioritised, client-relevant intelligence.
- Our analysis combines technical indicators with threat-actor, campaign, sector, and vulnerability context.
- Intelligence is assessed for freshness, reliability, confidence, and relevance before distribution.
- Indicators are enriched and deduplicated to reduce noise and improve operational value.
- Each development is translated into practical detection, mitigation, or monitoring actions.
- Intelligence can be tailored to an organisation's sector, geography, technology footprint, and risk priorities.
- Relevant intelligence can be operationalised through indicator packages, detection content, threat hunts, and executive reporting.
- Continuous monitoring supports timely escalation when a material change is identified.
- The service connects strategic context with tactical indicators and operational defensive actions.
- Analyst validation helps distinguish actionable signals from duplicative, stale, or low-confidence reporting.

# Email template 1: CTI service subscriber

**Subject:** Weekly Threat Intelligence Digest | `[Reporting Period]` | `[TLP]`

Dear `[Client Name/Team]`,

Please find below your Weekly Threat Intelligence Digest for **`[Reporting Period]`**. This edition highlights intelligence assessed as most relevant to your organisation's **`[Industry, Region, Technology Footprint, or Threat Profile]`**.

## Executive assessment

During the reporting period, we assessed the overall threat level as **`[Low/Moderate/High/Critical]`**. The principal developments were:

- **`[Threat/Campaign 1]`:** `[Concise explanation of relevance and potential impact]`
- **`[Threat/Campaign 2]`:** `[Concise explanation of relevance and potential impact]`
- **`[Vulnerability/Development]`:** `[Affected technology and exploitation status]`

## Priority intelligence

### `[Threat Actor, Malware, or Campaign Name]`

`[Describe the activity, targeting, motivation, observed tactics, and why it matters to the client.]`

- Targeted sectors or regions: `[Details]`
- Relevant MITRE ATT&CK techniques: `[Technique IDs and names]`
- Assessed confidence: `[High/Moderate/Low]`
- Intelligence source date: `[Date]`
- Recommended priority: `[Immediate/Elevated/Routine]`

## Indicators and detection opportunities

This week's validated intelligence package contains **`[Number]`** indicators, including:

- `[Number]` malicious or suspicious domains
- `[Number]` IP addresses
- `[Number]` URLs
- `[Number]` file hashes
- `[Number]` behavioural or detection patterns

The indicators have been deduplicated and reviewed for freshness and confidence. Low-confidence indicators and those associated with shared infrastructure should be used for detection and enrichment rather than automatic blocking.

## Recommended actions

1. `[Immediate defensive or investigative action]`
2. `[Threat-hunting or telemetry-review recommendation]`
3. `[Vulnerability remediation or exposure-validation action]`
4. `[Monitoring or stakeholder-awareness recommendation]`

## Outlook

Over the next `[Seven/Thirty]` days, we recommend heightened attention to **`[Campaign, Actor, Vulnerability, Event, or Geopolitical Development]`**. We will continue monitoring for material changes and issue an out-of-cycle alert if urgent action is required.

The detailed intelligence report and applicable indicator package are `[attached/available through the client portal]`. Please handle all information in accordance with **`[TLP]`**.

Kind regards,<br>
`[Analyst Name]`<br>
`[Title / Threat Intelligence Team]`<br>
`[Company]`<br>
`[Contact Details]`

# Email template 2: MDR, MDD, or IR client

**Subject:** Weekly Threat Digest and Defensive Actions | `[Reporting Period]`

Dear `[Client Name/Team]`,

Please find your weekly security threat digest for **`[Reporting Period]`**. This update summarises relevant external threats, notable activity identified through the services in scope, and the defensive actions recommended for your environment.

## Security posture summary

The overall risk level for this reporting period is assessed as **`[Low/Moderate/High/Critical]`**.

- Security alerts reviewed: `[Number]`
- Incidents requiring investigation: `[Number]`
- Confirmed security incidents: `[Number]`
- Threat hunts completed: `[Number]`
- Critical or actively exploited vulnerabilities identified: `[Number]`
- Outstanding client actions: `[Number]`

## Activity relevant to your environment

### `[Incident, Alert Trend, or Threat Development]`

`[Explain what was observed or why the external threat is relevant. Clearly distinguish confirmed client activity from broader threat intelligence.]`

- Environment status: `[Observed/Not Observed/Under Review/Telemetry Unavailable]`
- Affected assets or technologies: `[Details]`
- Detection status: `[Covered/Partially Covered/Additional Detection Recommended]`
- Response status: `[Contained/Monitoring/Client Action Required/Not Applicable]`

## Priority threats this week

- **`[Threat/Campaign]`:** `[Relevance, likely impact, and whether related activity was observed]`
- **`[Vulnerability]`:** `[Affected client technology, exploitation status, and remediation urgency]`
- **`[Attack Technique]`:** `[Behaviour to monitor and available detection coverage]`

## Actions completed by our team

- `[Detection rule deployed or tuned]`
- `[Threat hunt conducted and result]`
- `[Indicators added to monitoring or detection controls]`
- `[Incident-response or containment activity completed]`

## Recommended client actions

1. **`[Priority]`:** `[Action, affected system, owner, and recommended completion date]`
2. **`[Priority]`:** `[Action, affected system, owner, and recommended completion date]`
3. **`[Priority]`:** `[Action, affected system, owner, and recommended completion date]`

Please contact the `[SOC/MDR/IR]` team through **`[Support Channel or Emergency Contact]`** if you observe suspicious activity or require assistance implementing these recommendations. Urgent or high-confidence threats will continue to be communicated outside the weekly reporting cycle.

Kind regards,<br>
`[Service Manager/Analyst Name]`<br>
`[MDR/MDD/Incident Response Team]`<br>
`[Company]`<br>
`[Contact Details]`

# Email template 3: General cybersecurity CTI capability demonstration

**Subject:** Weekly Cyber Threat Intelligence Snapshot | `[Reporting Period]`

Dear `[Client Name/Team]`,

Please find our Cyber Threat Intelligence Snapshot for **`[Reporting Period]`**.

This sample digest demonstrates how our CTI capability transforms multi-source threat reporting and technical indicators into prioritised intelligence aligned with an organisation's sector, technology footprint, geographic presence, and risk priorities.

## This week's intelligence picture

We assessed **`[Threat, Campaign, or Vulnerability]`** as the most relevant development during the reporting period.

- Threat: `[Name or concise description]`
- Affected sectors: `[Sectors]`
- Affected technologies: `[Products or platforms]`
- Reported or observed activity: `[Concise campaign summary]`
- Potential impact: `[Operational or business consequences]`
- Assessment confidence: `[High/Moderate/Low]`
- Recommended priority: `[Immediate/Elevated/Routine]`

## Why this matters

`[Explain why the development is relevant to comparable organisations. Connect the threat to business operations, technology exposure, sector targeting, or third-party dependencies.]`

## From information to actionable intelligence

For this assessment, relevant reporting and indicators were:

- Collected from `[commercial, government, industry, and open-source]` intelligence sources;
- Correlated to identify infrastructure, malware, campaign, and threat-actor relationships;
- Deduplicated and enriched to improve accuracy and reduce noise;
- Assessed for freshness, confidence, and client relevance;
- Mapped to applicable MITRE ATT&CK techniques; and
- Translated into practical detection, mitigation, and monitoring recommendations.

## Recommended defensive actions

1. `[Exposure-validation recommendation]`
2. `[Detection or threat-hunting recommendation]`
3. `[Mitigation or remediation recommendation]`
4. `[Monitoring or awareness recommendation]`

## Indicators and detection opportunities

The associated intelligence package contains **`[Number]`** validated indicators and **`[Number]`** behavioural detection opportunities. Indicators assessed as low confidence or associated with shared infrastructure are recommended for monitoring and investigation rather than automatic blocking.

## How this can be tailored to your organisation

A subscribed service can prioritise intelligence according to your:

- Industry and geographic exposure;
- Critical technologies and internet-facing assets;
- Priority threat actors and attack techniques;
- Third-party and supply-chain dependencies; and
- Internal intelligence requirements and reporting audiences.

We would be pleased to provide a tailored intelligence briefing or sample assessment based on your organisation's threat profile.

Kind regards,<br>
`[Name]`<br>
`[Title / Cyber Threat Intelligence Team]`<br>
`[Company]`<br>
`[Contact Details]`

**Classification:** `[TLP:CLEAR or applicable designation]`

# Claims and wording guardrails

| Avoid                                       | Prefer                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------- |
| This actor definitely conducted the attack. | The activity is assessed as likely associated with the actor.                         |
| This indicator proves compromise.           | This indicator warrants investigation and correlation with additional evidence.       |
| Block all listed IP addresses.              | Validate context before blocking shared or low-confidence infrastructure.             |
| No threat exists.                           | No related activity was identified within the available scope.                        |
| The client is not affected.                 | Exposure could not be determined from the information currently available.            |
| Fully protected.                            | Detection or mitigation coverage is in place for the identified behaviour.            |
| Guaranteed prevention.                      | Intended to reduce the likelihood or impact of exploitation.                          |
| Real-time intelligence.                     | Continuously updated or frequently refreshed, unless delivery is genuinely real time. |
| Unique intelligence.                        | Proprietary or independently derived intelligence, only when demonstrably true.       |
| Confirmed malicious.                        | Suspicious or assessed as malicious, unless the evidence supports confirmation.       |

# Pre-distribution quality check

- [ ] All placeholders have been replaced.
- [ ] The reporting period and source dates are correct.
- [ ] Each priority item explains its relevance to the recipient.
- [ ] Observations, third-party reporting, and analytical assessments are clearly distinguished.
- [ ] Confidence statements match the supporting evidence.
- [ ] Attribution is appropriately qualified.
- [ ] IOC counts are deduplicated and current.
- [ ] Shared-infrastructure and low-confidence indicators are not recommended for automatic blocking.
- [ ] MDR/MDD/IR claims remain within the available telemetry and service scope.
- [ ] Prospect communications do not imply existing monitoring or confirmed exposure status.
- [ ] Every high-priority item has a practical recommended action.
- [ ] The TLP marking and source-sharing restrictions are correct.
- [ ] Names, titles, contact details, and portal links are correct.
- [ ] The final copy has been reviewed for clarity, grammar, and unsupported claims.
