# Changelog

All notable changes to xia_tan.

---

## v2.1 (2026-06-12)

### Critical Fixes

- **C1 ErrorBasedInjection baseline comparison precision** (`ErrorBasedInjection.java`)
  `detectError()` now returns the matched **regex pattern** instead of the database type name. Previously, if the baseline already contained *any* MySQL error (e.g. "Unknown column"), a *different* MySQL error triggered by a probe (e.g. "XPATH syntax error") would be skipped because both returned `"MySQL"`. Now the comparison is pattern-level, eliminating false negatives from same-DB different-error scenarios.

- **C2 simThreshold now affects SQLi strategies** (`AbstractInjectionStrategy.java`, `ScanEngine.java`)
  Added `setSimThreshold()` / `sim()` with ThreadLocal storage. `ScanEngine` injects the user-configured similarity threshold before each strategy executes. Previously, all 6 SQLi strategies hardcoded `0.9`, making the UI "Sim" parameter ineffective for SQLi detection.

- **C3 lastPayload thread safety** (all 6 strategy classes)
  Changed `lastPayload` from instance field to `ThreadLocal<String>`. Previously, concurrent parameter scans could race on this field, causing `getPayload()` to return another thread's payload — leading to incorrect evidence in scan reports.

### False Positive Elimination

- **Body size ratio filter** (`AbstractInjectionStrategy.isDifferentPage()`, all 6 strategies)
  Uses a practical, real-world heuristic: if a probe response body is <10% or >1000% of the baseline size, it's a different page (404/redirect/error), not SQLi. Normal page data variation (empty list vs full list) stays within 2-3x, well inside the [0.10, 10.0] threshold. No regex, no HTML parsing — just integer division. This replaces the earlier structural-similarity approach which failed on SPAs (all routes share the same empty HTML shell) and was O(n) regex over full response bodies.

### High-Priority Fixes

- **H1** `hashRequestBody`: Returns random UUID on exception instead of `""`, preventing silent dedup failure from empty-string collisions.
- **H2** `encodePayload(BASE64)`: Uses `getBytes("UTF-8")` instead of platform-default charset, matching the decoding side.
- **H3/H4** Null guards: Added `null` checks in `probeXSS_SSTI`, XSS Phase 2, and `TimeBasedInjection.execute()` for `param.value()`.
- **M6** `loadPersistedConfig`: Uses try-with-resources for FileReader (resource leak fix).

### Medium Fixes

- **M1** `OrderByInjection`: Removed dead code — unused `NAMES` set, `isOrderParam()` method, and `import java.util.*`.
- **M2** `StructuralSignature`: Strips query string from path before normalization, so `/api/user?id=1` and `/api/user?id=2` are correctly deduplicated.
- **M3** `StructuralSignature`: Removed redundant `.sorted()` inside `signature()` (caller already sorts).
- **M4** `MyCompare.segmentedSim`: Fixed header/tail overlap — tail now starts at `max(HEAD_SIZE, len-TAIL_SIZE)` instead of `len-TAIL_SIZE`.
- **L1** `EncodingDetector`: Hex detection now requires ≥8 characters (was ≥0), reducing false positives on short hex-like values.
- **L2** `MyCompare.levenshteinImpl`: Added 50K character cap to prevent OOM on unexpectedly large inputs.
- **TimeBasedInjection**: `timeThreshold` field now `volatile` for cross-thread visibility.

### Behavioral Changes

- `ErrorBasedInjection.detectError()` return type changed: now returns regex pattern string, not DB name. A new `detectErrorDB()` method returns the DB name for reporting purposes.
- `simThreshold` now actually affects Boolean-Blind, String, Numeric, and Order-By strategies — users changing the Sim slider will see real detection sensitivity changes.

---

## v2.0 (2026-06-11)

- Initial Montoya API release
- 6 SQLi strategies (Error-Based, Boolean-Blind, String, Numeric, Order-By, Time-Based)
- Unified similarity engine (MyCompare) with Jaccard + Levenshtein + upgradeStr
- REST API path deduplication (StructuralSignature)
- XSS / SSTI / NoSQLi detection
- Thread pool (10 workers) + ConcurrentHashMap dedup
- Filter Lists UI (2×2 blacklist/whitelist)
- Logs tab with real-time probe traffic
- Cookie encoding auto-detection (Base64/URL/Hex)
- CUD filtering (skip Create/Update/Delete endpoints)
