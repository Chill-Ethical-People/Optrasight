# Splunk SPL — Search Processing Language

**Platform**: Splunk Enterprise / Splunk Cloud  
**Family**: Pipe-delimited SPL  
**Comment syntax**: `` `comment("...")` `` macro (no native syntax)

## Structure

```
index=<index> sourcetype=<sourcetype> <search-terms> earliest=<time> latest=<time>
| <command1> ...
| <command2> ...
```

Every search begins with base filters (index, sourcetype, free-text) and then chains transforming commands with `|`. Time scope uses `earliest=` / `latest=`.

## Core building blocks for threat hunting

| Need | SPL |
|---|---|
| Time scope (last 24h) | `earliest=-24h latest=now` |
| Filter by field | `field_name="value"` or `field_name=value*` |
| IN list | `host IN ("h1", "h2")` |
| Regex match | `| regex field="pattern"` |
| Extract field | `| rex field=_raw "(?<user>\\w+@\\w+\\.\\w+)"` |
| Stats / aggregation | `| stats count by user, src_ip` |
| Top values | `| top limit=10 host` |
| Dedupe | `| dedup user` |
| Lookup IOC table | `| lookup iocs.csv ioc OUTPUT category` |
| Subsearch | `[ search index=auth failed | top limit=1 src_ip | fields src_ip ]` |
| Join | `| join src_ip [ search index=threat | fields src_ip, threat ]` |
| Time bucket | `| bin _time span=1h | stats count by _time, host` |
| Rolling window | `| streamstats time_window=1h count by user` |

## CIM-aligned fields for security

- Authentication: `src`, `dest`, `user`, `action` (success/failure), `app`
- Network: `src_ip`, `dest_ip`, `dest_port`, `bytes_out`, `bytes_in`
- Endpoint: `process`, `parent_process`, `process_path`, `parent_process_path`, `command_line`
- Web: `url`, `http_method`, `status`, `user_agent`, `referer`
- Email: `sender`, `recipient`, `subject`, `attachment_name`

## Hunting query examples

### Phishing email with suspicious attachment (1d)
```spl
index=email sourcetype=mail
  attachment_name=*.exe OR attachment_name=*.scr OR attachment_name=*.lnk OR attachment_name=*.iso
  earliest=-1d
| stats count by sender, recipient, attachment_name, subject
| where count > 1
| sort - count
```

### Credential stuffing — many failed logins from one IP
```spl
index=auth action=failure earliest=-1h
| stats dc(user) AS distinct_users, count by src_ip
| where distinct_users > 10
| sort - distinct_users
```

### LOLBin abuse — rundll32 with network connection
```spl
index=endpoint sourcetype=process
  (process_name=rundll32.exe OR process_name=regsvr32.exe OR process_name=mshta.exe)
  earliest=-7d
| join host, process_guid [
    search index=endpoint sourcetype=network
    | stats values(dest_ip) AS dest_ips by host, process_guid
  ]
| where isnotnull(dest_ips)
```

### Newly-seen suspicious domain in proxy traffic
```spl
index=proxy earliest=-1d
| stats earliest(_time) AS first_seen, count by dest_domain
| where first_seen > relative_time(now(), "-24h@h") AND count > 5
| eval domain_age_h = round((now()-first_seen)/3600, 1)
| sort - count
```

### Brand-abuse: lookalike domains in DNS logs
```spl
index=dns earliest=-7d
| eval distance=levenshtein(query, "yourbrand.com")
| where distance >= 1 AND distance <= 2 AND query != "yourbrand.com"
| stats count by query, src_ip
```

## Style guidelines

1. ALWAYS specify `index=` and `earliest=` to avoid full-history scans.
2. Use `tstats` for fast summary searches when CIM datamodels are accelerated.
3. Filter as early as possible — push narrowing terms to the base search.
4. Use `| fields` early to drop unused fields and speed up downstream commands.
5. Prefer `| stats` over `| eventstats` when you don't need to keep the raw rows.
