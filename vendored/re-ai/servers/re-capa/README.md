# re-capa

MCP server exposing [capa](https://github.com/mandiant/capa) (Mandiant) for capability detection with MITRE ATT&CK and MBC mappings.

## Tools

| Tool | What it does |
|---|---|
| `check_capa` | Version + rules path |
| `detect_capabilities` | Full capa report (JSON or vverbose) |
| `extract_mbc` | Just the Malware Behavior Catalog mappings |
| `find_interesting` | High-confidence / unique matches only |

## Install

```bash
pip install flare-capa
pip install -e ./servers/re-capa
```

## Why capa

capa finds *what* a binary does (capabilities) — at the function level — without telling you *how*. It maps to MITRE ATT&CK and the Malware Behavior Catalog. It's the highest-signal tool for the first 30 seconds of triage.

## Deprecation note

v1 `re-ai` had no capa wrapper either. The plugin used a custom string-search heuristic for ATT&CK, which is exactly the kind of thing capa does better in one pass.
