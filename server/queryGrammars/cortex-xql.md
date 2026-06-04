# Palo Alto Cortex XDR / XSIAM — XQL (Cortex Query Language)

**Platform**: Cortex XDR, Cortex XSIAM, Cortex Data Lake  
**Family**: Pipe-delimited, SQL-influenced  
**Comment syntax**: `//`  
**Reference**: [docs-cortex.paloaltonetworks.com](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Cortex-Query-Language-XQL)

## Structure

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS
  and action_process_image_name = "powershell.exe"
  and action_process_image_command_line contains "-enc"
| fields _time, agent_hostname, action_process_image_command_line, actor_process_image_name
| sort desc _time
| limit 100
```

Every XQL query begins with a `dataset` / `preset` / XDM source, then chains stages with `|`. The default dataset is `xdr_data`.

## Datasets

- `xdr_data` — default; all EDR + NGFW events
- `panw_ngfw_traffic_raw` — NGFW traffic
- `panw_ngfw_threat_raw` — NGFW threat logs
- `panw_ngfw_url_raw` — NGFW URL filtering
- `network_story` — story-aligned network events
- `endpoint_story` — story-aligned endpoint events

## XDM (Cortex Data Model) — preferred normalized schema

| XDM field | Description |
|---|---|
| `xdm.source.process.name` / `.command_line` / `.executable.path` | Source process |
| `xdm.target.process.name` / `.command_line` | Target / child process |
| `xdm.source.user.username` | User |
| `xdm.target.host.hostname` | Host |
| `xdm.network.application.protocol` | App layer protocol |
| `xdm.target.host.ipv4_addresses[]` | Target IPs |
| `xdm.network.dns.dns_question.name` | DNS query |
| `xdm.target.url.full` | URL |
| `xdm.source.file.sha256` | Source file hash |

## Stages and operators

| Need | XQL |
|---|---|
| Filter | `filter <expr>` |
| Select fields | `fields f1, f2 as alias` |
| Time bucket | `bin _time span=1h` |
| Aggregate | `comp count() by host` or `comp count(distinct user) by host` |
| Sort | `sort desc _time` |
| Limit | `limit 100` |
| Top | `top 10 by count` |
| Join | `join (dataset = b | filter ...) as B b.key = a.key` |
| Union | `union (dataset = b | filter ...)` |
| String funcs | `lowercase()`, `len()`, `replex()` (regex replace), `extract_substring()` |
| Regex | `... ~= ".*regex.*"` |
| Lookup | `lookup ioc_table.ioc as match` |
| CIDR | `incidr(ip, "10.0.0.0/8")` |

## Functions

- `arraystring(arr, ", ")` — array → string
- `coalesce(a, b)` — first non-null
- `to_string()`, `to_number()`, `to_timestamp()` — casts
- `extract_url_host(url)` — get host
- `extract_url_path(url)` — get path
- `geoip_country(ip)` — geo lookup
- `hostname_to_domain(h)` — strip subdomain
- `case when <cond> then <v> [...] else <v> end` — conditional

## Hunting query examples

### LOLBin spawned by Office app
```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS
  and actor_process_image_name in ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
  and action_process_image_name in ("rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","cmd.exe","powershell.exe")
| fields _time, agent_hostname, actor_effective_username,
         actor_process_image_name, action_process_image_name, action_process_image_command_line
| sort desc _time
| limit 200
```

### Brand-spoofing DNS request
```xql
dataset = xdr_data
| filter event_type = ENUM.NETWORK and action_app = "dns"
  and (dns_query_name ~= ".*y[o0]ur[\-]?brand.*" or dns_query_name ~= ".*yourbránd.*")
  and not dns_query_name ~= ".*\.yourbrand\.com$"
| comp count() as hits by dns_query_name, agent_hostname
| sort desc hits
```

### First-seen rare process hash (24h vs 30d)
```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and _time > to_timestamp(current_time() - 24*3600*1000)
| comp count() as today_count by action_process_image_sha256
| join (
    dataset = xdr_data
    | filter event_type = ENUM.PROCESS and _time > to_timestamp(current_time() - 30*24*3600*1000)
                            and _time < to_timestamp(current_time() - 24*3600*1000)
    | comp count() as historical_count by action_process_image_sha256
  ) as B B.action_process_image_sha256 = action_process_image_sha256
| filter historical_count = null
| sort desc today_count
```

### Failed RDP brute-force
```xql
dataset = xdr_data
| filter event_type = ENUM.SECURITY_EVENT and action_external_hostname = "rdp" and event_result = "FAILED"
| comp count() as failed, count(distinct actor_effective_username) as distinct_users by action_remote_ip
| filter failed > 20 and distinct_users > 3
| sort desc failed
```

## Style guidelines

1. Use the **XDM** schema where possible — it normalizes across data sources.
2. Always specify a `dataset` first (defaults to `xdr_data` but explicit is better).
3. Filter on indexed fields before computing.
4. `comp` is XQL's `stats` — use `count()`, `count(distinct ...)`, `min()`, `max()`, `avg()`.
5. Use `|` to chain stages; whitespace inside a stage doesn't matter.
