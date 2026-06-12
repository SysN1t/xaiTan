# Changelog

All notable changes to xia_tan.

---

## v2.1.2 (2026-06-12)

### SQL Injection — Minimum Payloads, Maximum Coverage

- **TimeBased 探针 16→5**：移除 `')` / `")' 括号闭合前缀（ErrorBased 已覆盖）和 Oracle DBMS_PIPE（边缘场景），仅保留 `'` + `"` 前缀覆盖 MySQL/MSSQL/PostgreSQL 三大 DB
- **ErrorBased 基础探针 6→3**：`'`, `"`, `')` 精简集。移除 `\`（增强探针 `%DF'` / `'"\\` 覆盖）、`'))` / `")`（多层括号闭合极罕见）
- **UnifiedString 前缀 4→2**：布尔盲注前缀 `'`, `')` , `'))`, `"` 变为 `'`, `"`。`')` / `'))` 由 ErrorBased 覆盖，不重复测试
- **NumericInjection 提前退出**：Phase 1（`-0-0-0`→`-abc`）发送探针后不执行 Phase 2（`1/0`→`1/1`）

### Persistence — Full Config Save/Restore

- **补全 12 个持久化字段**：模块开关 (XSS/SQLi/SSTI/NoSQLi/延时/Cookie/WAF)、CUD 开关 (增/删/改)、请求延迟、域名/路径白名单 — 全部写入 `~/.xia_tan/config.properties`，重启保留
- **UI 变更自动持久化**：Checkbox 切换和阈值输入均触发 1 秒防抖 `savePersistedConfig()`

### Real-Time Responsiveness

- **请求超时保护**：`send()` 和 `sendProbe()` 添加 20 秒超时，避免挂死目标阻塞扫描线程
- **日志批量刷新**：`ConcurrentLinkedQueue` + Swing Timer 每 500ms 清空队列写入 logModel，缓解 EDT 压力
- **线程池背压**：`ThreadPoolExecutor(4-10, bounded-200, CallerRunsPolicy)` 替代无界 `FixedThreadPool(10)`

### Critical Bug Fixes (from code review)

- **Levenshtein OOM**：`MAX_LEV` 50000→2000，超限回退 Jaccard
- **UnifiedString 静默失效**：`getSingleQuoteProbe()` 为 null 时自行发送 `'` 探针 fallback
- **WafBypass 线程安全**：`Random` → `ThreadLocalRandom`
- **ErrorBased 冗余正则**：由 ScanEngine 注入 `baselineSqlErr` 避免重复扫描
- **ProbeLogTableModel 上限**：`MAX_LOG_ENTRIES=5000`
- **配置保存失败 log**：不再静默吞噬异常
- **类命名规范**：`xia_tan` → `XiaTan`
- **Timer/线程池泄漏**：扩展卸载时 `dispose()` + `shutdown()` 清理
- **V2.1.1 版本号残留**：全部更新至 v2.1.2
- **isDifferentPage 重复代码**：统一到 AbstractInjectionStrategy 静态方法
- **setSimThreshold 重复设置**：提到参数循环外层
- **Checkbox 初始状态**：读取 scanEngine 实际值，重启后 UI 一致
- **flushPendingLogs 积压**：移除 50 条上限，全部清空
- **ProbeLogTableModel 行事件**：补 `fireTableRowsDeleted`
- **429 限流误报**：`isDifferentPage` 新增状态码检查，429 直接跳过
- **所有策略**：`isDifferentPage` 调用统一传入状态码

### Documentation

- 新增 `sql.md`：完整 SQL 注入检测流程、策略详解、防误报机制、场景案例分析

- 新增 `MyCompareTest`、`ResponseComparerTest`、`StructuralSignatureTest` 单元测试

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
