# Sigma — Generic Detection Rule Format

**Platform**: Vendor-agnostic rule format that compiles to Splunk SPL, KQL, Elastic, Chronicle YARA-L, QRadar AQL, LogScale CQL, Cortex XQL, etc.  
**Format**: YAML  
**Reference**: [github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

## Rule structure

```yaml
title: Suspicious PowerShell Encoded Command
id: 2026-05-13-pwsh-enc
status: stable
description: PowerShell launched with -enc flag and a long base64 blob, often used to bypass logging and evade signature detection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
author: optrasight
date: 2026/05/13
modified: 2026/05/13
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\powershell.exe'
  selection_args:
    CommandLine|re|i: '-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{40,}'
  filter_legitimate:
    ParentImage|endswith:
      - '\ServiceHub.SettingsHost.exe'
      - '\WindowsTerminal.exe'
  condition: selection_image and selection_args and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - Computer
falsepositives:
  - Legitimate admin scripts wrapped by SCCM / Intune
level: medium
```

## `logsource` taxonomy

```yaml
logsource:
  product: windows | linux | macos | azure | aws | gcp | okta | github | ...
  category: process_creation | network_connection | dns_query | file_event | image_load | registry_event | proxy | webserver | authentication | ...
  service: sysmon | security | sshd | wineventlog | ...
  definition: <freeform description if non-standard>
```

## `detection` blocks

Detection consists of one or more **search identifiers** (string keys) plus a **condition** that combines them with `and`, `or`, `not`, and `1 of`/`all of` aggregators.

Each search identifier is a mapping of field-to-value criteria. Use `|` modifiers on field names:

| Modifier | Meaning |
|---|---|
| `field` | exact match |
| `field|contains` | substring |
| `field|startswith` | prefix |
| `field|endswith` | suffix |
| `field|re` | regex (case sensitive) |
| `field|re|i` | regex (case insensitive) |
| `field|cidr` | IP CIDR |
| `field|gt` / `lt` / `gte` / `lte` | numeric compare |
| `field|all` | ALL listed values must match (logical AND across list) |

## Condition combinators

```
condition: selection
condition: selection and not filter
condition: 1 of selection_*
condition: all of selection_* and not 1 of filter_*
condition: selection | count() by Computer > 10
```

Aggregation `| count() by ... > N` is post-hit — supported by some backends (Splunk, Elastic) and emulated by others.

## Brand-abuse Sigma example

```yaml
title: DNS Query to Lookalike of yourbrand.com
id: 2026-05-13-yourbrand-lookalike
status: experimental
description: DNS query to a domain that resembles yourbrand.com but isn't a legitimate sub-domain.
author: optrasight
date: 2026/05/13
tags:
  - attack.initial_access
  - attack.t1566.002
logsource:
  category: dns_query
detection:
  selection:
    QueryName|re|i: 'y[o0]ur[\-]?brand|yourbránd'
  filter_legit:
    QueryName|endswith:
      - '.yourbrand.com'
  condition: selection and not filter_legit
fields:
  - QueryName
  - Computer
  - User
falsepositives:
  - Internal QA testing of lookalike URLs
level: medium
```

## Style guidelines

1. Use canonical Sigma field names — vendor-agnostic. Backends translate to native field names.
2. Always include `logsource` so the converter can pick the right pipeline.
3. Use modifier `|re|i` for case-insensitive regex — more portable than relying on backend defaults.
4. Add `filter_*` blocks for known false positives; reference them with `not filter_*` in the condition.
5. Use `tags:` with MITRE ATT&CK technique IDs so the rule registers in coverage maps.
6. `falsepositives:` is required for `stable` status.
7. `level:` MUST be one of: `informational`, `low`, `medium`, `high`, `critical`.
8. To **compile** Sigma to native syntax, use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or [Uncoder.io](https://uncoder.io/).
