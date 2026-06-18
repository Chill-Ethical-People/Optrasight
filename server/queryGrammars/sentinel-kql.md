# Microsoft Sentinel / Defender — KQL (Kusto Query Language)

**Platform**: Microsoft Sentinel, Microsoft Defender XDR (Advanced Hunting), Azure Monitor / Log Analytics  
**Family**: Pipe-delimited KQL  
**Comment syntax**: `//`  
**Case sensitivity**: Operators are case-sensitive (`==` exact, `=~` case-insensitive, `contains` insensitive, `contains_cs` sensitive)

## Structure

```kql
TableName
| where TimeGenerated > ago(1h)
| where Column1 == "value"
| project Column1, Column2
| summarize count() by Column1
| top 10 by count_ desc
```

Every query starts from a table (e.g. `SecurityEvent`, `SigninLogs`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `EmailEvents`) and chains operators with `|`.

## Common operators

| Need | KQL |
|---|---|
| Time scope | `where TimeGenerated > ago(24h)` or `between(datetime(...)..datetime(...))` |
| Filter | `where AccountName == "alice"` |
| Case-insensitive contains | `where ProcessCommandLine contains "powershell"` |
| Regex | `where Url matches regex @"https://.*\.tk/"` |
| Project (select fields) | `project Timestamp, DeviceName, AccountName` |
| Extend (compute) | `extend Domain = tostring(split(Url, "/")[2])` |
| Summarize | `summarize Count=count(), Users=dcount(AccountName) by DeviceName` |
| Top | `top 10 by Count desc` |
| Distinct | `distinct AccountName, DeviceName` |
| Join | `join kind=inner DeviceProcessEvents on DeviceId` |
| Union | `union DeviceNetworkEvents, DeviceFileEvents` |
| Time bucket | `summarize count() by bin(TimeGenerated, 1h)` |
| Bag/object access | `extend Foo = tostring(parse_json(Properties).foo)` |
| IPv4 range | `where ipv4_is_in_range(SrcIp, "10.0.0.0/8")` |
| Geo | `extend country = geo_info_from_ip_address(RemoteIP).country` |

## Defender XDR Advanced Hunting tables

- `DeviceProcessEvents` — process creation (with `InitiatingProcess*` parent fields)
- `DeviceNetworkEvents` — TCP/UDP connections
- `DeviceFileEvents` — file ops, downloads, deletes
- `DeviceImageLoadEvents` — DLL loads
- `DeviceLogonEvents` — logons (including failed)
- `DeviceRegistryEvents` — registry CRUD
- `EmailEvents` / `EmailUrlInfo` / `EmailAttachmentInfo` — M365 Defender mail
- `IdentityLogonEvents` / `AADSignInEventsBeta` — AAD signins
- `AlertInfo` / `AlertEvidence` — XDR alerts

## Sentinel-specific tables

- `SecurityEvent` (Windows agents) — event ID-based detection
- `Syslog` — Linux/syslog agents
- `SigninLogs`, `AuditLogs` — AAD
- `AzureActivity` — Azure control plane
- `OfficeActivity` — M365 audit
- `CommonSecurityLog` — CEF normalized

## Hunting query examples

### Suspicious LOLBin process chain
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Newly-seen domain in last 24h (proxy / DNS)
```kql
let baseline = DeviceNetworkEvents
| where Timestamp between (ago(30d)..ago(1d))
| summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(1d)
| summarize FirstSeen=min(Timestamp), Count=count() by RemoteUrl, DeviceName
| join kind=leftanti baseline on RemoteUrl
| where Count > 3
| order by Count desc
```

### Brand-spoofing email URL hunt
```kql
let target = "yourbrand";
EmailUrlInfo
| where Timestamp > ago(7d)
| extend HostPart = tostring(parse_url(Url).Host)
| where HostPart contains target and HostPart !endswith "yourbrand.com"
| join EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, HostPart
| order by Timestamp desc
```

### Credential brute-force from one IP
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedCount=count(), UniqueUsers=dcount(UserPrincipalName) by IPAddress, Location
| where FailedCount > 20 and UniqueUsers > 5
| order by FailedCount desc
```

### Lookalike domain registered against your brand
```kql
let brand = "yourbrand.com";
DeviceNetworkEvents
| where Timestamp > ago(24h)
| extend Hosts = extract_all(@"([a-z0-9\-]+\.[a-z]{2,})", tolower(RemoteUrl))
| mv-expand Host = Hosts
| extend H = tostring(Host)
| where H != brand and H endswith ".com"
| extend Distance = strlen(H) - strlen(replace_regex(H, @"[yourbrand]", ""))
| where Distance >= strlen(replace_regex(brand, @"\.com$", "")) - 1
| summarize Hits=count() by H
| order by Hits desc
```

## Style guidelines

1. Filter by `TimeGenerated` / `Timestamp` first — the engine prunes shards on time.
2. Use `has` / `has_cs` over `contains` when matching whole tokens (uses term index).
3. Prefer `summarize` aggregations to `extend`+`distinct`.
4. Use `let` to define reusable expressions (baseline tables, watchlists).
5. `project` early to reduce columns flowing through the pipeline.
