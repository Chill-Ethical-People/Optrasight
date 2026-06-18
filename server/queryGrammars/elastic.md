# Elastic — KQL / Lucene / EQL / ES|QL

**Platform**: Elasticsearch, Elastic Security (formerly SIEM), Kibana  
**Families**:
- **KQL (Kibana Query Language)** — discover bar, basic filtering (no regex, single index)
- **Lucene** — fallback for regex and complex boolean
- **EQL (Event Query Language)** — sequence/correlation detection
- **ES|QL** — modern piped query language (Elastic 8.11+)

**Comment syntax** — ES|QL uses `//`. KQL/Lucene have no comments.

## ECS field reference (used across all dialects)

- `@timestamp`, `event.action`, `event.category`, `event.outcome`
- `host.name`, `host.os.family`, `user.name`, `user.id`
- `process.name`, `process.args`, `process.parent.name`, `process.executable`, `process.hash.sha256`
- `source.ip`, `destination.ip`, `destination.port`, `destination.domain`, `url.full`, `url.domain`
- `file.path`, `file.name`, `file.hash.sha256`
- `network.protocol`, `network.bytes`

## KQL (Kibana Query Language)

Used in Discover, in rule queries, and in dashboards.

```kql
event.category:"process" and process.name:"powershell.exe" and process.args:"*-enc*"
```

| Need | KQL |
|---|---|
| Field exact | `process.name:"cmd.exe"` |
| Wildcards | `process.args:*powershell*` |
| IN list | `process.name:("cmd.exe" or "powershell.exe")` |
| Range | `destination.port>=1024 and destination.port<=65535` |
| Exists | `user.name:*` |
| Negation | `not process.parent.name:"explorer.exe"` |

KQL does **not** support regex. Use Lucene if you need it.

## Lucene

Toggle the search bar to Lucene mode for:

```lucene
process.args:/.*[Ee][Nn][Cc][Oo][Dd][Ee][Dd].*/
```

## EQL — sequence detection

Use for ordered behavior detection (e.g., MITRE ATT&CK technique chains). Each event in brackets is a stage that must occur in order.

```eql
sequence by process.pid with maxspan=2m
  [ process where process.name == "regsvr32.exe" ]
  [ library where stringContains(file.name, "scrobj.dll") ]
  until [ process where event.type == "termination" ]
```

```eql
// File created and then executed by the same process (potential dropper)
sequence by host.id with maxspan=5m
  [ file where event.type == "creation" and file.extension in ("exe","dll","ps1") ]
  [ process where event.type == "start" and process.executable like* "${file.path}" ]
```

## ES|QL — modern pipe syntax

```esql
FROM logs-endpoint.events-*
| WHERE @timestamp > NOW() - 1 day
| WHERE process.name == "powershell.exe"
| WHERE process.args LIKE "%-enc*%"
| STATS count = COUNT(*), users = COUNT_DISTINCT(user.name) BY host.name
| WHERE count > 5
| SORT count DESC
| LIMIT 20
```

| Need | ES\|QL |
|---|---|
| Source | `FROM index-pattern-*` |
| Filter | `WHERE col == "value"` |
| Aggregate | `STATS c = COUNT(*) BY field` |
| Compute | `EVAL domain = TO_LOWER(url.domain)` |
| Sort + limit | `SORT field DESC | LIMIT 100` |
| Dissect/extract | `DISSECT message "%{user} %{action}"` |
| Drop columns | `DROP large_field` |
| Keep columns | `KEEP a, b, c` |
| Rename | `RENAME a AS b` |
| Enrich (lookup) | `ENRICH ip-geo ON source.ip` |

## Hunting query examples

### Suspicious encoded PowerShell (KQL)
```kql
process.name:"powershell.exe" and (process.args:"-enc" or process.args:"-EncodedCommand")
  and not process.parent.name:("ServiceHub.SettingsHost.exe" or "explorer.exe")
```

### Lookalike brand domain (ES|QL)
```esql
FROM logs-network.dns-*
| WHERE @timestamp > NOW() - 7 days
| WHERE dns.question.name LIKE "*yourbrand*"
| WHERE NOT dns.question.name LIKE "*.yourbrand.com"
| STATS hits = COUNT(*) BY dns.question.name, host.name
| SORT hits DESC
| LIMIT 50
```

### Office spawning LOLBin (EQL)
```eql
sequence by host.id, process.entity_id with maxspan=10s
  [ process where process.name in ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE") ]
  [ process where process.name in ("rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","cmd.exe","powershell.exe") and process.parent.entity_id == process.entity_id ]
```

### Credential stuffing (ES|QL)
```esql
FROM logs-auth-*
| WHERE @timestamp > NOW() - 1 hour
| WHERE event.outcome == "failure"
| STATS failed = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip
| WHERE failed > 20 AND users > 5
| SORT failed DESC
```

## Style guidelines

1. KQL for simple filters, ES|QL for any transformation, EQL for sequences.
2. Always include a `@timestamp` filter or `FROM` time range.
3. Use ECS field names; avoid raw field names from custom pipelines.
4. KQL `:*` checks for existence (presence of a non-null value).
5. KQL is case-sensitive on `keyword` fields, case-insensitive on `text` fields.
