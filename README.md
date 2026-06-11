# xia_tan (瞎探) v2.0 — BurpSuite 多漏洞自动化探测插件

> **基于 xia_tan v1.0 二次开发** | Author: **SysN3t** | 迁移至 Montoya API，借鉴 [DetSql](https://github.com/saoshao/DetSql) 的 SQLi 检测优势重构。

通过修改请求参数对常见 Web 漏洞进行**自动化初步探测**的 BurpSuite 扩展插件。支持反射 XSS、SQL 注入（6 种检测策略）、SSTI 模板注入（6 大家族 20+ 引擎）、NoSQL 注入。

> **v2.0 重大更新**：迁移至 Montoya API（BurpSuite ≥ 2023.12.1），借鉴 [DetSql](https://github.com/saoshao/DetSql) 的 SQLi 检测优势，新增策略模式、统一相似度引擎、REST API 路径去重。

---

## 目录

- [功能特性](#功能特性)
- [检测原理](#检测原理)
- [扫描流程](#扫描流程)
- [配置说明](#配置说明)
- [编译与安装](#编译与安装)
- [使用方法](#使用方法)
- [项目结构](#项目结构)
- [注意事项](#注意事项)
- [更新日志](#更新日志)

---

## 功能特性

### 1. 反射 XSS 探测

- 注入唯一 HTML 标记 `<xia0tan>` 检测反射
- **未编码反射**（标签原样返回）→ 严重性 **High**
- **编码反射**（标记文本返回但 HTML 标签被编码）→ 严重性 **Info**
- 自动跳过 `Content-Type: application/json` 的响应（JSON 响应无 XSS 风险）
- 基线中已包含标记时自动跳过（降噪）

### 2. SQL 注入探测（6 种策略）

借鉴 DetSql 的策略模式，每种策略独立执行、命中即停。

| 策略 | 类型 | 检测方式 |
|------|------|---------|
| ErrorBased | 报错注入 | `'`, `"`, `\` 触发语法错误，正则匹配 10 种数据库 91+ 特征 |
| BooleanBlind | 布尔盲注 | `'\|\|EXP(710)\|\|'` / `'\|\|EXP(290)\|\|'` / `'\|\|1/1\|\|'` 三步对照 |
| StringInjection | 字符型注入 | `'` → `''` → `'+'` → `'\|\|'` 四步阶梯验证 |
| NumericInjection | 数字型注入 | `-0-0-0`（等价变换）→ `-abc`（语法破坏）对比验证 |
| OrderByInjection | ORDER BY 注入 | `,0` → `,xxxxxx` → `,1` / `,2` 阶梯验证 |
| TimeBasedInjection | 延时注入 | SLEEP / WAITFOR 轮询 + 基线耗时 2x 判定 |

**支持的数据库（10 种）**：MySQL / MariaDB, MSSQL, PostgreSQL, Oracle, SQLite, DB2, Informix, Sybase, MS Access, HQL / Hibernate

### 3. SSTI 模板注入探测

覆盖 **6 大家族 20+ 模板引擎**，每个家族使用不同的唯一操作数，通过计算结果精确定位被执行的模板语法。

| 表达式语法 | 覆盖引擎 | 操作数示例 |
|-----------|---------|-----------|
| `{{A*B}}` | Jinja2, Twig, Pebble, Nunjucks, Handlebars, Smarty3 | 91371×91373 |
| `${A*B}` | Freemarker, Mako, Groovy, EL/JSP, Velocity, Thymeleaf | 91374×91376 |
| `<%=A*B%>` | ERB (Ruby), EJS (Node.js), ASP | 91377×91379 |
| `#{A*B}` | SpEL (Spring), Jade/Pug | 91380×91382 |
| `@(A*B)` | Razor (.NET) | 91383×91385 |
| `{A*B}` | Smarty2 (PHP) | 91386×91388 |

与 XSS 探测合并在同一请求中发送，节省请求数量。基线中已包含计算结果时自动跳过（降噪）。

### 4. NoSQL 注入探测

- **操作符注入**（仅 JSON 请求体）：`$gt`, `$ne`, `$regex`, `$exists`, `$where`
- **错误检测**：匹配 MongoDB, CouchDB, Elasticsearch, Cassandra, Redis 等 24 种错误特征
- 仅对 JSON 请求体发送探针，避免无效请求

### 5. 其他功能

- **Cookie 参数探测**：勾选后扫描 Cookie 中的参数
- **Cookie 编码自动检测**：Base64/URL/Hex 编码自动解码后注入、重新编码发送
- **请求头注入**：探测 User-Agent / Referer / X-Forwarded-For / X-Real-IP
- **CUD 过滤**：默认跳过增/删/改接口
- **黑白名单**：2×2 面板，域名+路径各含白名单/黑名单，实时计数，支持通配符
- **Logs 标签页**：所有探测流量实时展示，点击查看完整数据包
- **手动停止**：一键取消所有进行中扫描
- **两层去重**：REST 路径签名 + SHA-256 内容哈希
- **模块独立**：XSS/SSTI/SQLi/NoSQLi 互不干扰，SQLi 内部命中即停
- **排序**：表格点击列头排序

---

## 检测原理

### 响应相似度引擎 (MyCompare)

统一相似度引擎，整合 xia_tan 原有的行级 Jaccard 相似度与 DetSql 的 6 个核心优势：

#### ① upgradeStr — 前后缀剥离
比较前先剥离两个响应的公共前缀和后缀，再删除 POC 痕迹。对微小差异远敏感于直接进行整行 Jaccard 比较。

```
原始: "abcXdef" 与 "abcYdef"
剥离: ["X", "Y"]
比较: X 与 Y → 相似度 0.0 ✅
```

#### ② 长度差辅助判定
- `|lenA − lenB| ≤ 1` → 直接判定相似度 100%
- `|lenA − lenB| ≥ 100` → 直接判定相似度 0%

#### ③ 大响应分段比较
响应体大于 50KB 时，仅比较前 10KB 与后 5KB 的 Jaccard 行级相似度均值。

#### ④ Levenshtein 快速失败
- 长度差超过 `maxLen × (1 − threshold)` → 提前返回 0.0
- 前 100 字符差异超过 50 → 提前返回 0.0

#### ⑤ REST API 路径去重 (StructuralSignature)
将路径中的动态段替换为占位符后再去重，避免同一接口的不同实例被重复扫描：

```
/user/123      → /user/{int}
/api/550e8400... → /api/{uuid}
/session/a1b2c3d4 → /session/{hex}
```

#### ⑥ 请求超时与重试
`CompletableFuture.get(20, SECONDS)` 超时控制 + 最多 2 次重试，防止线程池被挂起的请求永久占用。

### 布尔盲注多步对照算法（借鉴 DetSql）

字符型注入采用四步阶梯验证（以 StringInjection 为例）：

```
步骤1: '      单引号 → 期望破坏语法（与基线不同）
步骤2: ''     双引号 → 期望修复语法（与步骤1不同）
步骤3: '+'    拼接空字符串 → 期望还原原始响应（与基线相同）→ ✅ 确认注入
步骤4: '||'   备选拼接（Oracle / PostgreSQL 语法兼容）
```

每次仅需 3~4 个请求，通过多步对照大幅降低误报。

### 基线对比降噪

- **SQL 报错**：基线响应中已存在的数据库错误特征（含数据库类型 + 具体模式）不会被重复报告
- **NoSQL 报错**：同上
- **XSS 标记**：基线中已包含 `xia0tan` 标记则跳过该参数的 XSS 检测
- **SSTI 计算结果**：基线中已包含运算结果则跳过该家族的 SSTI 检测

---

## 扫描流程

```
每个参数的完整扫描流程：

Phase 1: XSS + SSTI 合并探测 ........................ 1 request
  └─ 一个 payload 同时测试 HTML 反射 + 6 种模板语法
  └─ JSON 响应自动跳过 XSS 检测

Phase 2: SQLi 策略链 ............................... 2~12 requests
  ├─ ErrorBased:    报错探针 (', ", \, '"\\) → 匹配10种数据库错误
  ├─ BooleanBlind:  EXP(710) / EXP(290) / 1/1 布尔对照
  ├─ String:        ', '', '+', '||' 四步验证
  ├─ Numeric:       -0-0-0 / -abc 对比验证（仅数字参数）
  ├─ OrderBy:       ,0 / ,xxxxxx / ,1 / ,2 阶梯验证（仅排序参数）
  └─ TimeBased:     SLEEP / WAITFOR 延时检测（可由 Time 开关控制）
  → 任一策略命中即停止本参数探测

Phase 3: NoSQLi 操作符注入 ......................... 1~5 requests
  └─ $gt / $ne / $regex / $exists / $where（仅 JSON 请求体）

总计: 每个参数约 3~15 个请求（绝大多数情况 5~8 个）
```

---

## 配置说明

### 检测模块开关

| 选项 | 说明 | 默认 |
|------|------|------|
| XSS | 反射 XSS 检测 | ✅ 启用 |
| SQLi | SQL 注入检测 | ✅ 启用 |
| SSTI | 模板注入检测 | ✅ 启用 |
| NoSQLi | NoSQL 注入检测 | ✅ 启用 |
| Time | 延时注入检测 | ✅ 启用 |
| Cookie | Cookie 参数探测 | ❌ 关闭 |

### CUD 增删改扫描开关

控制是否扫描增/删/改操作的接口，**默认全部关闭**以避免对业务数据产生副作用。

| 选项 | 说明 | 默认 | 匹配关键词 |
|------|------|------|-----------|
| 增(C) | 创建/新增类接口 | ❌ 关闭 | create, insert, save, register, signup, upload, submit, add, new, post, write |
| 删(D) | 删除类接口 | ❌ 关闭 | delete, remove, destroy, purge, del, drop, erase, clear |
| 改(U) | 修改/更新类接口 | ❌ 关闭 | update, edit, modify, change, patch, alter, set, put, revise |

**路径匹配规则**：按 `/` 分割路径段，逐段检查是否以关键词开头并跟随驼峰边界或分隔符（大写字母、`_`、`-`、`.`）。例如 `/api/deleteUser` ✅ 匹配，`/api/delivery` ❌ 不匹配。

### Filter Lists（可视化黑白名单）

点击 `▸ 过滤器列表` 按钮展开过滤器管理面板，2×2 网格包含四个列表：

- **✅ 域名白名单**：仅扫描这些域名，空 = 全部允许
- **🔒 域名黑名单**：不扫描这些域名，支持通配符（如 `*.baidu.com`），默认含 42 个 CDN/统计域名
- **✅ 路径白名单**：仅扫描这些路径，空 = 全部允许
- **🔒 路径黑名单**：不扫描这些路径，支持通配符（如 `*.css`），默认含 98 个静态文件后缀

每项支持输入框 + `+` 按钮添加，选中后点 `− Remove Selected` 删除，配置实时生效。

### 域名匹配规则

输入的域名自动清洗（去除 `http://` / `https://` 前缀、端口号和尾部 `/`），然后做精确比对：

| 输入 | 清洗后 | 匹配效果 |
|------|--------|---------|
| `example.com` | `example.com` | 精确匹配 |
| `https://example.com:8080/` | `example.com` | 精确匹配 |
| `*.example.com` | `*.example.com` | 匹配子域名 |
| `*` | `*` | 匹配所有域名 |

### 参数与阈值

| 选项 | 说明 | 默认值 |
|------|------|--------|
| Exclude params | 排除的参数名（逗号分隔） | `csrf,token,_t,timestamp` |
| Delay(ms) | 请求间隔毫秒数 | `0` |
| Time(ms) | 延时注入判定阈值 | `4000` |
| Sim | 响应相似度阈值 (0.0~1.0) | `0.9` |

### 自动过滤规则

以下内容会被自动跳过，无需手动配置：

- **静态资源**：`.js`, `.css`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`, `.woff`, `.woff2`, `.ttf`, `.eot`, `.mp3`, `.mp4`, `.avi`, `.pdf`, `.zip`, `.rar`, `.map`, `.webp`, `.bmp`
- **二进制响应**：`image/*`, `audio/*`, `video/*`, `application/octet-stream`, `application/pdf`, `application/zip`
- **Cookie 参数**：默认不扫描，需勾选 **Cookie** 开关手动启用
- **超长参数值**：值长度 ≥ 512 字符的参数自动跳过
- **REST API 去重**：`/user/123` 和 `/user/456` 视为同一接口，不重复扫描
- **XML / Multipart**：不扫描 XML 属性和 Multipart 属性参数

---

## 编译与安装

### 环境要求

- JDK 1.8+
- BurpSuite **≥ 2023.12.1**（需支持 Montoya API）
- Montoya API JAR（编译依赖，首次编译自动从 Maven Central 下载）

### 编译

```bash
# 下载 Montoya API 依赖
curl -L -o lib/montoya-api-2026.4.jar \
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.4/montoya-api-2026.4.jar

# 编译所有源文件
javac --release 8 -cp lib/montoya-api-2026.4.jar \
  -d build/classes -encoding UTF-8 \
  src/main/java/burp/xia_tan.java \
  src/main/java/burp/*.java \
  src/main/java/burp/util/*.java \
  src/main/java/burp/injection/*.java

# 打包 JAR
jar cf build/libs/xia_tan-2.0.jar -C build/classes burp
```

产物路径：`build/libs/xia_tan-2.0.jar`

### 安装

1. 打开 BurpSuite（需 ≥ 2023.12.1 版本）
2. 进入 **Extensions** → **Installed** → **Add**
3. Extension type 选择 **Java**
4. 选择编译好的 `xia_tan-2.0.jar`
5. 加载成功后会出现 `xia_tan` 标签页

---

## 使用方法

### 手动扫描

在 Proxy / Repeater / Target 等模块中右键请求：
- **Send to xia_tan** — 使用当前 UI 配置进行全量扫描（XSS + SQLi + SSTI + NoSQLi）
- **xia_tan scan...** → 选择特定检测类型单独扫描

### 自动监控

勾选 **Proxy** 和 / 或 **Repeater** 复选框，插件会自动拦截经过的请求并进行扫描。建议配合 Domain Whitelist 限定目标范围。

### 查看结果

左侧上方 **Results** 表格展示所有发现：

| 列 | 说明 |
|----|------|
| # | 序号 |
| Host | 目标主机 |
| M | HTTP 方法 (GET / POST) |
| URL | 请求路径 |
| Param | 注入参数名 |
| Type | 漏洞类型 (XSS / SQLi / SSTI / NoSQLi) |
| Severity | 严重性 (High / Medium / Info) |
| Detail | 检测细节与 payload |
| Code | HTTP 状态码 |

点击结果行，右侧 **Request / Response** 查看器显示该漏洞对应的完整请求与响应。

### Logs 标签页

左侧下方 **Logs** 表格实时展示所有探测流量：

| 列 | 说明 |
|----|------|
| # | 序号 |
| Time | 发送时间 (HH:mm:ss) |
| Method | HTTP 方法 |
| URL | 请求路径 |
| Param | 参数名 |
| Payload | 注入 payload（>80 字符自动截断显示） |
| Code | HTTP 状态码 |
| Len | 响应体长度 (bytes) |
| Elap | 响应耗时 (ms) |

点击 Logs 行，右侧查看器显示该次探测的完整请求与响应数据包，无需再到 Burp 的 HTTP History 中翻找。**Clear** 按钮同时清空 Results 和 Logs。

### 严重性说明

| 颜色 | 级别 | 含义 |
|------|------|------|
| 🔴 红色底色 | High | 高置信度确认（报错注入命中、布尔盲注确认、延时确认、未编码 XSS 反射、SSTI 运算确认） |
| 🟠 橙色底色 | Medium | 中置信度（NoSQLi 操作符响应差异等，建议人工确认） |
| ⬜ 白色底色 | Info | 信息性（编码反射等） |

---

## 项目结构

```
xia_tan/
├── lib/                                   # 编译依赖
│   └── montoya-api-2026.4.jar             # Burp Montoya API
├── build/libs/                            # 编译产物
│   └── xia_tan-2.0.jar
└── src/main/java/burp/
    ├── xia_tan.java                       # 插件入口 (BurpExtension + HttpHandler + 右键菜单)
    ├── ScanEngine.java                    # 核心扫描引擎 + 过滤 + 日志记录
    ├── XiaTanPanel.java                   # UI 面板 + Filter Lists 管理器
    ├── ScanResult.java                    # 结果数据模型
    ├── ScanTableModel.java                # 结果表格模型
    ├── ProbeLogTableModel.java            # 探测日志表格模型
    ├── XSSDetector.java                   # 反射 XSS 检测
    ├── SSTIDetector.java                  # SSTI 模板注入检测（6 大家族 20+ 引擎）
    ├── NoSQLiDetector.java                # NoSQL 注入检测（操作符 + 错误特征）
    ├── ResponseComparer.java              # 域名 / 路径匹配
    ├── util/
    │   ├── MyCompare.java                 # 统一相似度引擎（Jaccard + Levenshtein + upgradeStr）
    │   └── StructuralSignature.java       # REST API 路径去重（动态段 → 占位符）
    └── injection/
        ├── AbstractInjectionStrategy.java # 注入策略抽象基类（超时控制 + 请求重试）
        ├── ErrorBasedInjection.java       # 报错注入（10 种数据库）
        ├── BooleanBlindInjection.java     # 布尔盲注（EXP 对照算法）
        ├── StringInjection.java           # 字符型注入（四步阶梯验证）
        ├── NumericInjection.java          # 数字型注入（等价变换对比）
        ├── OrderByInjection.java          # ORDER BY 注入（阶梯验证）
        └── TimeBasedInjection.java        # 延时注入（SLEEP / WAITFOR 轮询）
```

---

## 注意事项

1. **仅用于授权的安全测试**，未经授权的扫描属于违法行为
2. **BurpSuite 版本要求**：需 ≥ 2023.12.1（Montoya API），低于此版本请使用 [v1.0](https://github.com/saoshao/DetSql)
3. **所有探测 payload 均为只读操作**（触发语法错误、数学运算、延时函数），不包含 INSERT / UPDATE / DELETE / DROP 等任何写操作，不会对数据库数据产生增删改
4. **CUD 开关默认关闭**，扫描增删改接口可能在业务侧产生副作用（如创建垃圾数据），请按需开启
5. **Cookie 开关默认关闭**，启用前建议在 `Exclude params` 中排除认证相关 Cookie（如 session、JSESSIONID 等），避免因篡改认证信息导致请求失败
6. **延时注入**（SLEEP / WAITFOR 等）会占用服务器连接，建议在非生产环境或低峰期使用，可通过 Time 开关关闭
7. 建议先配置 **Domain Whitelist** 限定目标范围，避免扫描非目标站点
8. 所有配置修改**实时生效**，无需点击保存按钮

---

## 更新日志

### v2.0 (2026-06)

- **API 迁移**：从 Legacy `IBurpExtender` 全面迁移至 Montoya `BurpExtension`（需 BurpSuite ≥ 2023.12.1）
- **借鉴 DetSql**：SQLi 检测重构为 6 个独立策略类，采用策略模式
- **统一相似度引擎** (MyCompare)：整合 Jaccard + Levenshtein + upgradeStr 前后缀剥离 + 长度差辅助判定 + 大响应分段比较 + 快速失败
- **REST API 路径去重** (StructuralSignature)：`/user/123` → `/user/{int}`，避免重复扫描
- **请求超时控制**：`CompletableFuture.get(20s)` + 最多 2 次重试
- **Filter Lists**：可视化域名白名单 / 路径黑白名单管理面板
- **Logs 标签页**：所有探测流量实时展示，点击即可查看完整数据包
- **发现即停**：任一 SQLi 策略命中后自动停止当前参数的后续探针
- **UI 重构**：左右分栏布局，Results / Logs 表格 + Request / Response 查看器
- **线程安全**：AtomicInteger + ConcurrentHashMap + synchronized + SwingUtilities.invokeLater
- **危害性清理**：RANDOMBLOB 500MB→5MB，BENCHMARK 1000万→300万次，ST_Buffer 移除，SSTI RCE payload 替换为安全运算
- **误报收紧**：基线对照覆盖全部检测点、NoSQLi ReferenceError 收紧为数据库相关模式、延时注入增加基线耗时 2x 判定

### v1.0

- 初始版本，基于 Legacy Burp Extender API
- XSS / SQLi / SSTI / NoSQLi 四大检测模块
- 行级 Jaccard 相似度算法 + 布尔盲注多步对照算法
- CUD 路径过滤 + 域名/路径黑白名单

---

## 致谢

- **原始 xia_tan v1.0** — 本插件基于 xia_tan v1.0 二次开发而来，保留了 XSS 检测、SSTI 检测、NoSQLi 检测的核心逻辑
- [DetSql](https://github.com/saoshao/DetSql) — SQLi 检测策略与相似度算法的灵感来源，布尔盲注、字符型、数字型、ORDER BY 注入策略借鉴自 DetSql
- [PortSwigger](https://portswigger.net/) — BurpSuite 平台与 Montoya API

---

## 开源协议

MIT License
