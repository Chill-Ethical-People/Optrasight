# CrowdStrike Falcon LogScale — CQL (CrowdStrike Query Language) / Humio

**Platform**: CrowdStrike Falcon NG-SIEM, CrowdStrike LogScale (formerly Humio)  
**Family**: Pipe-delimited functional language  
**Comment syntax**: `// single-line`, `/* multi-line */`  
**Reference**: [library.humio.com/data-analysis/syntax.html](https://library.humio.com/data-analysis/syntax.html)

## Structure

```cql
#repo=base
| event_simpleName=ProcessRollup2
| FileName=/powershell\.exe/i
| top([UserName, ComputerName], limit=10)
```

Queries are built by chaining filters and functions with `|`. Each stage receives events from the previous stage. The query is anchored either by free-text or by repository (`#repo=...`) and field filters.

## Filters

| Need | CQL |
|---|---|
| Free-text grep | `"failed login"` |
| Field equals | `UserName="alice"` |
| Field IN list | `in(UserName, values=["a","b","c"])` |
| Field regex (case-insensitive) | `FileName=/powershell\.exe/i` |
| Field regex with named groups | `command_line=/\\-enc(?<encoded>\S+)/i` |
| NOT match | `!UserName="root"` |
| Wildcards | `FileName="*powershell*"` |
| Compare numerics | `bytes_out > 1000000` |
| Time range (relative) | `@timestamp >= -1h` |

## Common stages

- `head(N)` / `tail(N)` — take first/last N
- `top(field, limit=10)` — top values
- `sort(field, order=desc)` — sort
- `groupBy(field, function=count())` — aggregate
- `bucket(span=1h, function=count())` — time bucket
- `select([f1, f2])` — keep only listed fields
- `format(format="%s -> %s", field=[a, b], as=arrow)` — string format
- `case { x=1 | newField:="one"; * | newField:="other" }` — conditional
- `match(file="iocs.csv", column=ioc)` — lookup table

## Falcon EDR fields (event_simpleName)

- `ProcessRollup2` — process exec (FileName, CommandLine, UserName, ComputerName, ParentBaseFileName, MD5HashData, SHA256HashData)
- `DnsRequest` — DNS query (DomainName, ContextProcessId)
- `NetworkConnectIP4` / `NetworkConnectIP6` — outbound connections (RemoteAddressIP4, RemotePort)
- `SuspiciousDnsRequest` — Falcon-flagged DNS
- `ScriptControlScanInfo` — PowerShell / VBA / JS content
- `UserLogon` / `UserLogonFailed2` — logons
- `RegistryOperationDetected` — registry changes
- `FileWritten` / `FileDeleted` — file ops
- `ImageHash` — module loads

## Hunting query examples

### Suspicious PowerShell encoded command
```cql
#event_simpleName=ProcessRollup2
| FileName=/powershell\.exe/i
| CommandLine=/\-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+(?<b64>[A-Za-z0-9+\/=]{40,})/i
| select([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
| top([ComputerName, UserName], limit=20)
```

### LOLBin spawned by Office
```cql
#event_simpleName=ProcessRollup2
| in(FileName, values=["rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe"])
| in(ParentBaseFileName, values=["winword.exe","excel.exe","powerpnt.exe","outlook.exe"])
| groupBy([ComputerName, ParentBaseFileName, FileName], function=count())
| sort(_count, order=desc)
```

### Brand-abuse: lookalike domain in DNS
```cql
#event_simpleName=DnsRequest
| DomainName=/(?:y[o0]urbrand|y[o0]ur-brand|yourbránd)/i
| !DomainName=/yourbrand\.com$/i
| groupBy([DomainName, ComputerName], function=count())
| sort(_count, order=desc)
```

### Newly-observed IP in outbound traffic (last 24h vs 30d baseline)
```cql
// Last 24h
#event_simpleName=NetworkConnectIP4 @timestamp >= -24h
| RemoteAddressIP4 != ""
| groupBy(RemoteAddressIP4, function=count(as=hits_24h))
// Anti-join against 30d baseline using a Live Query / scheduled view
| match(file="baseline_30d_ips.csv", column=ip, strict=false)
| !matched
| sort(hits_24h, order=desc, limit=100)
```

### Credential brute-force
```cql
#event_simpleName=UserLogonFailed2 @timestamp >= -1h
| groupBy([RemoteAddressIP4, UserName], function=count(as=failed))
| where(failed > 5)
| groupBy(RemoteAddressIP4, function=count(field=UserName, as=distinct_users))
| where(distinct_users > 5)
| sort(distinct_users, order=desc)
```

## Style guidelines

1. ALWAYS anchor with `#repo=` or `#event_simpleName=` to avoid scanning every record.
2. Filter on indexed fields before computing new ones.
3. Use `groupBy()` rather than `top()` when you need multi-key aggregation.
4. Use `match(file=..., column=..., strict=false)` to anti-join against watchlists.
5. Date math: `@timestamp >= -1h` is fastest for relative windows.
