# xia_tan v2.0 — BurpSuite Multi-Vulnerability Scanner

> **A complete rewrite of xia_tan v1.0** | Author: **SysN3t** | Montoya API (BurpSuite ≥ 2023.12.1) | Incorporating SQLi detection strategies from [DetSql](https://github.com/saoshao/DetSql).

## Quick Start

**Requirements**: BurpSuite ≥ 2023.12.1, JDK 1.8+

**Install**: Extensions → Add → Java → select `xia_tan-2.0.jar`

**Full documentation**: see [README.md](README.md) (Chinese)

## Features

- **XSS** — reflected XSS via unique HTML marker `<xia0tan>`
- **SQLi** — 6 strategy chain: Error-based, Boolean blind, String, Numeric, ORDER BY, Time-based
- **SSTI** — 6 template engine families (20+ engines)
- **NoSQLi** — MongoDB/CouchDB/Elasticsearch operator injection + error detection
- **CUD Filter** — skip Create/Update/Delete endpoints by default
- **Filter Lists** — 2×2 grid (Domain WL/BL, Path WL/BL) with 42 default blocked domains + 98 blocked extensions
- **Logs Tab** — real-time probe traffic viewer with full request/response inspection
- **REST API Dedup** + **SHA-256 Content Dedup** — avoid redundant scans
- **Module Independence** — XSS/SSTI/SQLi/NoSQLi run independently
- **Cookie Encoding** — auto-detect Base64/URL/Hex, decode→inject→re-encode
- **Header Injection** — probes User-Agent/Referer/X-Forwarded-For/X-Real-IP
- **Manual Stop** — cancel all running scans instantly
- **Table Sorting** — click column headers to sort results/logs

## Detection Strategies (SQLi)

| Strategy | Approach |
|----------|----------|
| ErrorBased | `'`, `"`, `\` triggers → regex match 10 DB error patterns |
| BooleanBlind | `EXP(710)` overflow vs `EXP(290)` normal vs `1/1` confirm |
| StringInjection | `'` → `''` → `'+'` → `'||'` 4-step ladder |
| NumericInjection | `-0-0-0` (equiv) vs `-abc` (syntax break) |
| OrderByInjection | `,0` → `,xxxxxx` → `,1` / `,2` ladder |
| TimeBasedInjection | SLEEP/WAITFOR polling + 2× baseline timing |

## Similarity Engine (MyCompare)

6 improvements over vanilla Jaccard:

1. **upgradeStr** — strip common prefix/suffix before diff
2. **Length-diff fast path** — ≤1 → 100%, ≥100 → 0%
3. **Large body segmentation** — >50KB: compare head 10KB + tail 5KB
4. **Levenshtein fast fail** — bail early on extreme length/prefix divergence
5. **REST path normalization** — `/user/123` → `/user/{int}`
6. **Timeout + retry** — `CompletableFuture.get(20s)`, max 2 retries

## Build

```bash
javac --release 8 -cp lib/montoya-api-2026.4.jar -d build/classes \
  src/main/java/burp/xia_tan.java \
  src/main/java/burp/*.java \
  src/main/java/burp/util/*.java \
  src/main/java/burp/injection/*.java

jar cf build/libs/xia_tan-2.0.jar -C build/classes burp -C src/main/resources xia_tan.properties
```

## License

MIT — see [README.md](README.md) for full credits and changelog.
