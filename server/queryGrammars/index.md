# Query Syntax Reference — OptraSight AI Hunting

This directory is the canonical knowledge base OptraSight's AI hunt-query generator consults when producing native queries for each customer's SIEM/EDR platform. Each MD file is a self-contained primer on one platform's query language and is loaded into the AI system prompt at runtime.

## Platforms covered

| File | Platform | Language | Family |
|---|---|---|---|
| `splunk.md` | Splunk Enterprise / Cloud | SPL | Pipe-delimited |
| `sentinel-kql.md` | Microsoft Sentinel + Defender XDR | KQL (Kusto) | Pipe-delimited |
| `crowdstrike-cql.md` | CrowdStrike Falcon NG-SIEM + LogScale (Humio) | CQL | Pipe-delimited functional |
| `elastic.md` | Elastic Security / Elasticsearch | KQL + Lucene + EQL + ES\|QL | Mixed |
| `cortex-xql.md` | Palo Alto Cortex XDR / XSIAM | XQL (XDM) | Pipe-delimited, SQL-influenced |
| `qradar-aql.md` | IBM QRadar | AQL (Ariel) | SQL-like |
| `chronicle-yaral.md` | Google Security Operations (Chronicle) | YARA-L 2.0 + UDM Search | Rule-based |
| `sumologic.md` | Sumo Logic Cloud SIEM | Sumo Search | Pipe-delimited |
| `sigma.md` | Sigma (vendor-agnostic, compiles to all) | Sigma YAML | Detection rule format |

## Vendor → file mapping

When the user picks "CrowdStrike" as their platform, the AI consults `crowdstrike-cql.md` (since Falcon's current SIEM is built on the Humio engine).

| Vendor selection | File loaded |
|---|---|
| **Splunk** | `splunk.md` |
| **Microsoft Sentinel** / **Microsoft Defender** / **Microsoft 365 Defender** | `sentinel-kql.md` |
| **CrowdStrike** / **Falcon LogScale** / **Humio** | `crowdstrike-cql.md` |
| **Elastic** / **Elasticsearch** / **Elastic Security** | `elastic.md` |
| **Palo Alto Cortex** / **Cortex XDR** / **Cortex XSIAM** | `cortex-xql.md` |
| **IBM QRadar** / **QRadar** | `qradar-aql.md` |
| **Google SecOps** / **Chronicle** | `chronicle-yaral.md` |
| **Sumo Logic** | `sumologic.md` |
| **Sigma** (generic) | `sigma.md` |

## How the AI uses these references

1. The user selects one or more target platforms in the Hunt Query dialog.
2. The dispatcher reads the corresponding MD files from this directory.
3. The contents are embedded into the AI system prompt as authoritative grammar for that platform.
4. The AI generates platform-native queries against the requested IOCs / hypotheses, using:
   - The platform's own keyword set, pipe stages, and field names
   - The platform's preferred time-range syntax
   - The platform's preferred case-sensitivity and regex flavor
   - The platform's hunting-style idioms (e.g. `tstats` for Splunk CIM, `match:` for YARA-L)
5. The mock multi-language templates already shipped with v2.11 are kept as a fallback when no key is configured.

## Maintenance

When a vendor changes their syntax (e.g. Sentinel introducing new tables, Cortex updating XDM fields, Falcon adding NG-SIEM operators), append the updated info to the relevant MD file and re-deploy. The AI dispatcher reads the file at request time, so no rebuild is needed — but for production we bundle the directory into the server image at build time.

## Field reference policy

The "Hunting query examples" sections in each file are not exhaustive cookbooks. They establish the **shape** of a well-written query — anchor, filter chain, aggregation, sort/limit — for that platform. The AI is expected to compose its own queries using the platform's grammar, not to repeat the examples verbatim.

Where MITRE ATT&CK technique IDs appear in examples, the AI should preserve them in `tags:` (Sigma) / `mitre_attack:` (YARA-L) / inline comments (everywhere else) to support coverage mapping.
