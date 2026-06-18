# Sumo Logic — Search Query Language

**Platform**: Sumo Logic Cloud SIEM, Continuous Intelligence Platform  
**Family**: Pipe-delimited  
**Comment syntax**: `//`  

## Structure

```sumo
_sourceCategory=auth/* "failed"
| parse "user=*" as user
| parse "src=*" as src_ip
| where !isBlank(user)
| count by user, src_ip
| where _count > 10
| sort by _count desc
```

Queries begin with a metadata filter (`_sourceCategory`, `_source`, `_collector`, `_index`), then chain operators with `|`.

## Metadata filters (anchors)

- `_sourceCategory=prod/auth/sshd`
- `_source="Linux Hosts"`
- `_collector="us-west-1"`
- `_index=security` (for partitions)
- `_messageTime` / `_receiptTime` (implicit, set by time picker)

## Common operators

| Need | Sumo |
|---|---|
| Free-text grep | `"failed login"` |
| Parse field | `parse "user=*," as user` (anchor-based) |
| Parse regex | `parse regex "user=(?<user>[^,]+)"` |
| Field exists | `where !isBlank(user)` |
| Numeric compare | `where status_code >= 400` |
| Aggregate | `count by user, src_ip` |
| Sum / dc | `count, count_distinct(user) by src_ip` |
| Top | `top 10 src_ip by _count` |
| Time bucket | `timeslice 1h` then `count by _timeslice, host` |
| Lookup CSV | `lookup category from "shared/iocs.csv" on ioc=domain` |
| Subquery | `... | join (... by user) as a` |
| GeoIP | `lookup latitude, longitude, country_code from geo://default on ip=src_ip` |

## Parse expressions

The `parse` operator is anchor-based — give it the text around the field you want:

```sumo
parse "ssh2: Failed password for invalid user * from * port *"
  as user, src_ip, src_port
```

`parse regex` for full regex with named groups:

```sumo
parse regex "(?<src_ip>\d+\.\d+\.\d+\.\d+).*user=(?<user>[\w\-\.]+)"
```

## Hunting query examples

### Failed SSH brute-force
```sumo
_sourceCategory=*/auth/sshd "Failed password"
| parse "from * port" as src_ip
| parse "for invalid user *" as user nodrop
| where !isBlank(src_ip)
| count, count_distinct(user) as users by src_ip
| where _count > 20 and users > 3
| sort by _count desc
```

### Newly-seen domain in proxy logs
```sumo
_sourceCategory=prod/proxy
| parse "host=\"*\"" as host
| where !isBlank(host)
| timeslice 1d
| min(_messagetime) as first_seen by host
| where first_seen > (now() - 24*60*60*1000)
```

### Brand spoofing in DNS
```sumo
_sourceCategory=prod/dns
| parse "query: *" as query
| where matches(query, "y[o0]ur[\\-]?brand.*") and !matches(query, ".*\\.yourbrand\\.com$")
| count by query, _sourceHost
| sort by _count desc
```

### Suspicious PowerShell process
```sumo
_sourceCategory=windows/sysmon "Image:*\\powershell.exe"
| parse "CommandLine: *" as cmd nodrop
| parse "User: *" as user nodrop
| parse "Computer: *" as host nodrop
| where matches(cmd, ".*-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\\s+[A-Za-z0-9+/=]{40,}.*")
| count by host, user, cmd
| sort by _count desc
```

## Style guidelines

1. Always include a `_sourceCategory` (or `_source`) filter to limit ingestion volume scanned.
2. Use `parse` (anchor-based) before `parse regex` for speed.
3. Use `nodrop` to keep rows where parsing fails — otherwise rows are silently filtered.
4. Use `timeslice` before aggregation to bucket time.
5. Reserved `_` fields are read-only and start with underscore (`_messagetime`, `_raw`, `_count`, `_sourceCategory`).
