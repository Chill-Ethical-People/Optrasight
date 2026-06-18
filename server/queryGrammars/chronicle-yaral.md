# Google Chronicle (Google Security Operations) — YARA-L 2.0 + UDM Search

**Platform**: Google Security Operations (formerly Chronicle SIEM)  
**Families**:
- **YARA-L 2.0** — detection-rule language with `events:` / `match:` / `outcome:` / `condition:` sections
- **UDM Search** — interactive search syntax for the Search UI

**Comment syntax**: `// single-line`, `/* multi-line */`  
**Reference**: [docs.cloud.google.com/chronicle/docs/yara-l/](https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples)

## UDM event schema essentials

UDM is the Unified Data Model — every event maps into normalized fields:

- `metadata.event_type` — NETWORK_CONNECTION, PROCESS_LAUNCH, USER_LOGIN, EMAIL_TRANSACTION, FILE_CREATION, DNS, etc.
- `principal.*` — actor (host, user, process, ip, port)
- `target.*` — target (host, user, process, ip, port, url, file, registry)
- `src.*` / `observer.*` — source / observer when distinct
- `network.*` — protocol, direction, dns.question.name, http.user_agent
- `security_result.*` — verdict (action_details, threat_name, severity)
- `principal.process.command_line`, `target.process.command_line`
- `principal.hostname`, `principal.ip`, `principal.user.userid`

## UDM Search (interactive)

Used in the Search bar. Supports basic operators:

```udm
metadata.event_type = "PROCESS_LAUNCH"
  AND target.process.file.full_path = /powershell\.exe/ nocase
  AND target.process.command_line = /-enc/ nocase
```

Operators: `=`, `!=`, `>`, `<`, `>=`, `<=`, `AND`, `OR`, `NOT`, `IN`, regex literal `/.../[nocase]`.

## YARA-L 2.0 rules

```yara
rule SuspiciousPowershellEncoded {
  meta:
    author = "optrasight"
    description = "PowerShell with -enc and large base64 blob"
    severity = "Medium"
    mitre_attack = "T1059.001, T1027"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\.exe$/ nocase
    $e.target.process.command_line = /-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
    $host = $e.principal.hostname
  match:
    $host over 5m
  outcome:
    $risk_score = max(50)
    $command = array_distinct($e.target.process.command_line)
  condition:
    $e
}
```

Section meanings:
- `events:` — declare event variables (`$e`, `$net`, `$login`) and field filters
- `match:` — what to group by, with a time window (`over 5m`, `over 1h`)
- `outcome:` — computed outcome variables (risk score, list of values)
- `condition:` — boolean expression that must hold (`$e and $login`)

## YARA-L correlation example — sequence detection

```yara
rule OfficeSpawnsLOLBin {
  meta:
    description = "Office app spawns rundll32 / regsvr32 / mshta / wscript / cscript"
    severity = "High"
    mitre_attack = "T1218, T1059"
  events:
    $office.metadata.event_type = "PROCESS_LAUNCH"
    $office.target.process.file.full_path = /(winword|excel|powerpnt|outlook)\.exe$/ nocase
    $lolbin.metadata.event_type = "PROCESS_LAUNCH"
    $lolbin.target.process.file.full_path = /(rundll32|regsvr32|mshta|wscript|cscript|cmd|powershell)\.exe$/ nocase
    $lolbin.principal.process.pid = $office.target.process.pid
    $host = $office.principal.hostname
  match:
    $host over 10m
  condition:
    $office and $lolbin
}
```

## YARA-L brand-abuse example

```yara
rule LookalikeBrandDomainInDNS {
  meta:
    description = "DNS request to a lookalike of yourbrand.com"
    severity = "Medium"
  events:
    $d.metadata.event_type = "NETWORK_DNS"
    $d.network.dns.questions.name = /y[o0]ur[\-]?brand|yourbránd/ nocase
    $d.network.dns.questions.name != /\.yourbrand\.com$/ nocase
    $host = $d.principal.hostname
  match:
    $host over 1h
  outcome:
    $domains = array_distinct($d.network.dns.questions.name)
  condition:
    $d
}
```

## YARA-L non-existence / anomaly

```yara
rule NewHostNotInBaseline {
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.hostname = $h
    not $baseline.principal.hostname = $h  // unbounded: $baseline not seen
  match:
    $h over 1h
  condition:
    $e and !$baseline
}
```

## Style guidelines

1. UDM fields are dotted paths — always normalize to `principal/target/src` semantics.
2. Use `nocase` for case-insensitive regex literals.
3. `match:` requires every event variable that appears in `condition:` to bind through it.
4. `or` between event variables is NOT supported — use multiple rules.
5. `condition:` can include outcome bounds (`$risk_score > 50`) for tunable severity.
6. Time windows in `match:` should be the smallest realistic window for the detection.
