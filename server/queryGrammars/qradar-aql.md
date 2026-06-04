# IBM QRadar — AQL (Ariel Query Language)

**Platform**: IBM QRadar SIEM (on-prem + Cloud)  
**Family**: SQL-like  
**Comment syntax**: None (use saved-search descriptions)

## Structure

```aql
SELECT
  sourceip, destinationip, username, eventcount, starttime
FROM events
WHERE category = 8001
  AND username ILIKE '%admin%'
START '2026-01-01 00:00' STOP '2026-01-02 00:00'
ORDER BY starttime DESC
LIMIT 100
```

AQL mirrors SQL: `SELECT ... FROM events|flows WHERE ... GROUP BY ... HAVING ... ORDER BY ... LIMIT N` with QRadar-specific time clauses (`START ... STOP ...`, `LAST <N> <UNIT>`).

## Tables

- `events` — event records (Ariel event database)
- `flows` — netflow records
- `simarc` — historical correlated offenses

## Time clauses

| Need | AQL |
|---|---|
| Absolute range | `START '2026-01-01 00:00' STOP '2026-01-02 00:00'` |
| Relative | `LAST 24 HOURS` (or MINUTES, DAYS) |
| Within an hour | `LAST 1 HOURS` |

## Useful built-in properties

- `sourceip`, `destinationip`, `sourceport`, `destinationport`
- `protocolid` (numeric), `protocolname`
- `username`, `eventcount`, `magnitude`, `severity`
- `category` (QRadar category ID), `qid` (event QID)
- `logsourcename`, `logsourcetypename`
- `starttime`, `endtime`, `devicetime`
- `payload` (raw event text — use sparingly, no index)

## Custom event/flow properties

Reference custom properties with double quotes when they contain spaces:

```aql
SELECT "Source URL", "User Agent" FROM events
WHERE "Source URL" ILIKE '%/wp-admin/%'
LAST 1 HOURS
```

## Operators & functions

| Need | AQL |
|---|---|
| Like (case-insensitive) | `ILIKE '%term%'` |
| Regex | `MATCHES '^abc.*'` (POSIX) |
| IN list | `username IN ('alice', 'bob')` |
| CIDR | `INCIDR('10.0.0.0/8', sourceip)` |
| Count | `COUNT(*)`, `COUNT(DISTINCT username)` |
| Aggregate group | `GROUP BY sourceip` |
| HAVING | `HAVING COUNT(*) > 10` |
| String funcs | `LOWER()`, `UPPER()`, `SUBSTRING(s, start, len)`, `STRLEN(s)` |
| Cast | `DOUBLE()`, `LONG()`, `STR()` |
| IP to text | `STR(sourceip)` |
| Reference set lookup | `username IN (REFERENCESET('vip_users'))` |

## QID and category mapping

`category` and `qid` are numeric. Common categories:
- `4001` — Successful login
- `4002` — Failed login
- `8001` — Authentication (umbrella)
- `5018` — Stream allowed
- `5019` — Stream denied

Use the QRadar GUI to look up category IDs; AQL doesn't expose the name directly without joining the reference data.

## Hunting query examples

### Brute-force from a single IP (failed logins)
```aql
SELECT sourceip,
       COUNT(*) AS failed,
       COUNT(DISTINCT username) AS distinct_users
FROM events
WHERE category = 4002
GROUP BY sourceip
HAVING failed > 20 AND distinct_users > 3
LAST 1 HOURS
ORDER BY failed DESC
```

### Newly-seen destination IP in flows
```aql
SELECT destinationip,
       COUNT(*) AS hits
FROM flows
WHERE destinationip NOT IN (REFERENCESET('known_egress_ips'))
  AND NOT INCIDR('10.0.0.0/8', destinationip)
  AND NOT INCIDR('172.16.0.0/12', destinationip)
GROUP BY destinationip
HAVING hits > 5
LAST 24 HOURS
ORDER BY hits DESC
LIMIT 100
```

### Lookalike brand domain in proxy logs
```aql
SELECT "Destination Host", username, COUNT(*) AS hits
FROM events
WHERE logsourcetypename = 'Proxy'
  AND "Destination Host" MATCHES 'y[o0]ur[\-]?brand\\..*'
  AND "Destination Host" NOT ILIKE '%yourbrand.com'
GROUP BY "Destination Host", username
LAST 7 DAYS
ORDER BY hits DESC
```

### Suspicious PowerShell with encoded command
```aql
SELECT sourceip, destinationip, username, "Process Command Line"
FROM events
WHERE logsourcetypename ILIKE '%Sysmon%'
  AND "Process Name" ILIKE '%powershell.exe'
  AND "Process Command Line" MATCHES '.*-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\\s+[A-Za-z0-9+/=]{40,}.*'
LAST 7 DAYS
ORDER BY starttime DESC
LIMIT 100
```

## Style guidelines

1. ALWAYS use `LAST N <UNIT>` or `START/STOP` — Ariel partitions by time.
2. Use `REFERENCESET()` for watchlist semantics; do not hard-code allowlists.
3. Prefer custom properties over `payload` searches (payload is unindexed).
4. `GROUP BY` requires every non-aggregated `SELECT` field to be in the group key.
5. `MATCHES` is POSIX regex — double-escape backslashes in your editor.
