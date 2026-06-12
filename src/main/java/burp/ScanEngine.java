package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.*;
import java.util.*;
import burp.injection.*;
import burp.util.*;

import javax.swing.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.UUID;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

public class ScanEngine {

    private final MontoyaApi api;
    private final ExecutorService executor;
    private final Set<String> scannedSigs = ConcurrentHashMap.newKeySet();
    private final Map<String, Future<?>> activeScans = new ConcurrentHashMap<>();
    private ScanTableModel tableModel;
    private ProbeLogTableModel logModel;
    private final AtomicInteger resultCounter = new AtomicInteger(0);
    private final List<AbstractInjectionStrategy> sqliStrategies;
    private final TimeBasedInjection timeBased;

    private static final int MAX_PARAM_LEN = 512;
    private static final String[] STATIC_EXTS = {
        ".js",".css",".png",".jpg",".jpeg",".gif",".svg",".ico",
        ".woff",".woff2",".ttf",".eot",".mp3",".mp4",".avi",
        ".pdf",".zip",".rar",".map",".webp",".bmp"
    };
    private static final String[] ADD_KW = {"create","insert","save","register","signup","upload","submit","add","new","post","write"};
    private static final String[] DEL_KW = {"delete","remove","destroy","purge","del","drop","erase","clear"};
    private static final String[] MOD_KW = {"update","edit","modify","change","patch","alter","set","put","revise"};

    volatile boolean enableXSS=true, enableSQLi=true, enableSSTI=true, enableNoSQLi=true;
    volatile boolean enableTimeSQLi=true, enableCookie=false;
    volatile boolean enableWafBypass=true;
    volatile boolean scanAdd=false, scanDel=false, scanMod=false;
    volatile int delayMs=0;
    volatile long timeThreshold;
    volatile double simThreshold;
    volatile String excludeParams;
    volatile String domainWhitelist, domainBlacklist, pathBlacklist, pathWhitelist;

    {
        // 从 xia_tan.properties 加载默认配置
        java.util.Properties props = new java.util.Properties();
        try (java.io.InputStream in = getClass().getResourceAsStream("/xia_tan.properties")) {
            if (in != null) props.load(in);
        } catch (Exception ignored) {}
        timeThreshold  = Long.parseLong(props.getProperty("time.threshold", "5000"));
        simThreshold   = Double.parseDouble(props.getProperty("sim.threshold", "0.9"));
        excludeParams  = props.getProperty("exclude.params", "csrf,token,_t,timestamp");
        domainWhitelist = "";
        domainBlacklist = props.getProperty("domain.blacklist", "");
        pathBlacklist  = props.getProperty("path.blacklist", "");
        pathWhitelist  = "";
    }

    public ScanEngine(MontoyaApi api) {
        this.api = api;
        this.executor = Executors.newFixedThreadPool(10);
        // 从持久化存储加载用户配置（首次启动用 properties 文件默认值）
        loadPersistedConfig();
        this.sqliStrategies = Arrays.asList(
            new ErrorBasedInjection(api),
            new UnifiedStringInjection(api),
            new NumericInjection(api),
            new OrderByInjection(api)
        );
        // TimeBased is separate — gated by cfg.timeSqli
        this.timeBased = new TimeBasedInjection(api);
    }

    public void setTableModel(ScanTableModel m) { this.tableModel = m; }
    public void setLogModel(ProbeLogTableModel m) { this.logModel = m; }
    public void clearDedup() { scannedSigs.clear(); }

    public void cancelScan(String scanId) { Future<?> f = activeScans.remove(scanId); if (f != null) f.cancel(true); }
    public void cancelAllScans() { for (Future<?> f : activeScans.values()) f.cancel(true); activeScans.clear(); }

    // ==================== 持久化配置 ====================

    private static File configFile() {
        return new File(System.getProperty("user.home"), ".xia_tan/config.properties");
    }

    private void loadPersistedConfig() {
        File f = configFile();
        if (!f.exists()) return;
        try {
            java.util.Properties p = new java.util.Properties();
            try (java.io.FileReader reader = new java.io.FileReader(f)) {
                p.load(reader);
            }
            domainBlacklist = p.getProperty("domain.blacklist", domainBlacklist);
            pathBlacklist   = p.getProperty("path.blacklist", pathBlacklist);
            excludeParams   = p.getProperty("exclude.params", excludeParams);
            timeThreshold   = Long.parseLong(p.getProperty("time.threshold", String.valueOf(timeThreshold)));
            simThreshold    = Double.parseDouble(p.getProperty("sim.threshold", String.valueOf(simThreshold)));
        } catch (Exception e) {
            api.logging().logToOutput("[xia_tan] 配置加载失败，使用默认值: " + e.getMessage());
        }
    }

    public void savePersistedConfig() {
        File f = configFile();
        try {
            f.getParentFile().mkdirs();
            java.util.Properties p = new java.util.Properties();
            p.setProperty("domain.blacklist", nvl(domainBlacklist));
            p.setProperty("path.blacklist", nvl(pathBlacklist));
            p.setProperty("exclude.params", nvl(excludeParams));
            p.setProperty("time.threshold", String.valueOf(timeThreshold));
            p.setProperty("sim.threshold", String.valueOf(simThreshold));
            p.store(new java.io.FileWriter(f), "xia_tan v2.1.1 user config");
        } catch (Exception ignored) {}
    }

    private static String nvl(String s) { return s != null ? s : ""; }

    static class ScanConfig {
        boolean xss, sqli, ssti, nosqli, timeSqli, cookie, wafBypass, scanAdd, scanDel, scanMod;
        int delay; long timeThresh; double simThresh;
        String excludeP, domainWL, domainBL, pathBL, pathWL;
    }

    ScanConfig captureConfig() {
        ScanConfig c = new ScanConfig();
        c.xss=enableXSS; c.sqli=enableSQLi; c.ssti=enableSSTI; c.nosqli=enableNoSQLi;
        c.timeSqli=enableTimeSQLi; c.cookie=enableCookie; c.wafBypass=enableWafBypass;
        c.delay=delayMs; c.timeThresh=timeThreshold; c.simThresh=simThreshold;
        c.excludeP=excludeParams; c.domainWL=domainWhitelist; c.domainBL=domainBlacklist;
        c.pathBL=pathBlacklist; c.pathWL=pathWhitelist;
        c.scanAdd=scanAdd; c.scanDel=scanDel; c.scanMod=scanMod;
        return c;
    }

    ScanConfig buildSelectiveConfig(boolean xss, boolean sqli, boolean ssti, boolean nosqli) {
        ScanConfig c = captureConfig();
        c.xss=xss; c.sqli=sqli; c.ssti=ssti; c.nosqli=nosqli;
        return c;
    }

    public String scanAsync(HttpRequestResponse rr) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        Future<?> f = executor.submit(() -> {
            try { doScan(rr, captureConfig()); } finally { activeScans.remove(id); }
        });
        activeScans.put(id, f);
        return id;
    }
    public void scanAsync(HttpRequestResponse rr, ScanConfig c) {
        String id = UUID.randomUUID().toString().substring(0, 8);
        Future<?> f = executor.submit(() -> {
            try { doScan(rr, c); } finally { activeScans.remove(id); }
        });
        activeScans.put(id, f);
    }

    // ==================== Core Scan Logic ====================

    private void doScan(HttpRequestResponse baseRR, ScanConfig cfg) {
        HttpRequest req = baseRR.request();
        String host = baseRR.httpService().host();
        String path = req.path();
        String method = req.method();

        if (!ResponseComparer.isDomainAllowed(host, cfg.domainWL)) {
            api.logging().logToOutput("[xia_tan] SKIP domain WL: " + host); return;
        }
        if (ResponseComparer.isDomainBlocked(host, cfg.domainBL)) {
            api.logging().logToOutput("[xia_tan] 🚫 SKIP domain BL: " + host + " (blocked)");
            return;
        }
        if (cfg.domainBL != null && !cfg.domainBL.trim().isEmpty()) {
            api.logging().logToOutput("[xia_tan] ALLOW domain: " + host + " (BL=[" + cfg.domainBL + "])");
        }
        if (ResponseComparer.isPathBlocked(path, cfg.pathBL)) {
            api.logging().logToOutput("[xia_tan] SKIP path BL: " + path); return;
        }
        if (!ResponseComparer.isPathAllowed(path, cfg.pathWL)) {
            api.logging().logToOutput("[xia_tan] SKIP path WL: " + path); return;
        }
        if (isStatic(path)) {
            api.logging().logToOutput("[xia_tan] SKIP static: " + path); return;
        }
        if (isCudBlocked(path, cfg)) {
            api.logging().logToOutput("[xia_tan] SKIP CUD: " + path); return;
        }

        String baseBody = baseRR.response()!=null ? baseRR.response().bodyToString() : "";
        if (baseBody.isEmpty()) return;

        String respCt = contentType(baseRR);
        if (isBinary(respCt)) return;
        // Check request Content-Type for JSON (NoSQLi needs JSON request body)
        String reqCt = req.headerValue("Content-Type");
        boolean isJsonReq = reqCt != null && reqCt.toLowerCase().contains("json");

        // 两层去重：REST 路径签名 + 内容哈希
        String sig = StructuralSignature.signature(method, path,
                req.parameters().stream().map(ParsedHttpParameter::name)
                        .sorted().collect(java.util.stream.Collectors.toList()));
        if (!scannedSigs.add(sig)) return;

        // SM3/SHA-256 内容去重（相同请求体不重复扫描）
        String bodyHash = hashRequestBody(req);
        if (!scannedSigs.add("body:" + bodyHash)) return;

        String baselineSqlErr = ErrorBasedInjection.detectError(baseBody);
        String baselineNoSqlErr = NoSQLiDetector.detectError(baseBody);
        Set<String> excl = parseSet(cfg.excludeP);

        // 扫描 URL/body 参数（含编码检测）
        boolean sqliFound = false;
        for (ParsedHttpParameter param : req.parameters()) {
            if (excl.contains(param.name().toLowerCase())) continue;
            String pv = param.value();
            if (pv == null || pv.length() > MAX_PARAM_LEN) continue;
            if (scanWithEncoding(req, baseRR, param, baseBody, cfg, host, method, path, respCt, isJsonReq, baselineSqlErr, baselineNoSqlErr, excl)) {
                sqliFound = true;
                break;
            }
        }

        // 请求头注入探测（仅当 SQLi 未命中时）
        if (cfg.sqli && !sqliFound) {
            probeHeaderInjection(req, baseBody, cfg, host, method, path, baselineSqlErr);
        }

        // Cookie 参数（仅当 SQLi 未命中时）
        if (cfg.cookie && !sqliFound) {
            for (HttpParameter param : extractCookieParams(req)) {
                if (excl.contains(param.name().toLowerCase())) continue;
                String cv = param.value();
                if (cv == null || cv.length() > MAX_PARAM_LEN) continue;
                if (scanWithEncoding(req, baseRR, param, baseBody, cfg, host, method, path, respCt, isJsonReq, baselineSqlErr, baselineNoSqlErr, excl)) break;
            }
        }
    }

    // ==================== Header Injection ====================

    private static final String[] INJECTABLE_HEADERS = {
        "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"
    };

    private void probeHeaderInjection(HttpRequest req, String baseBody, ScanConfig cfg,
                                       String host, String method, String path,
                                       String baselineSqlErr) {
        for (String headerName : INJECTABLE_HEADERS) {
            String origValue = req.headerValue(headerName);
            if (origValue == null || origValue.isEmpty()) continue;

            // 用原始值重置（避免上次探测残留累积）
            String cleanValue = origValue.replaceAll("['\"\\\\]+$", "");

            // 发送探针 1: 单引号
            delay(cfg);
            HttpRequest modReq1 = req.withHeader(headerName, cleanValue + "'");
            HttpRequestResponse rr1 = sendProbe(modReq1, path, headerName, "'");
            if (rr1 == null || rr1.response() == null) continue;
            String body1 = rr1.response().bodyToString();

            // 发送探针 2: 双引号（正交验证，排除随机波动）
            delay(cfg);
            HttpRequest modReq2 = req.withHeader(headerName, cleanValue + "\"");
            HttpRequestResponse rr2 = sendProbe(modReq2, path, headerName, "\"");
            if (rr2 == null || rr2.response() == null) continue;
            String body2 = rr2.response().bodyToString();

            // 体量异常过滤：修改 Header 导致 404/302 → 非注入
            if (isHeaderProbeDiffPage(baseBody, body1)
                    || isHeaderProbeDiffPage(baseBody, body2)) continue;

            // 两个探针都产生差异才确认（排除单次网络波动）
            // 小响应体 (<500B) 用 Levenshtein 替代 Jaccard
            boolean smallBody = baseBody.length() < 500;
            double sim1 = smallBody ? MyCompare.levenshtein(baseBody, body1)
                                    : MyCompare.similarity(baseBody, body1);
            double sim2 = smallBody ? MyCompare.levenshtein(baseBody, body2)
                                    : MyCompare.similarity(baseBody, body2);
            double threshold = smallBody ? 0.85 : cfg.simThresh;

            if (sim1 < threshold && sim2 < threshold) {
                String err = ErrorBasedInjection.detectError(body1);
                String sev = (err != null && (baselineSqlErr == null || !baselineSqlErr.equals(err)))
                        ? "High" : "Medium";
                report(host, method, path, headerName, "SQLi",
                        "Header Injection", "Header '" + headerName
                                + "' sim1=" + MyCompare.fmt(sim1) + " sim2=" + MyCompare.fmt(sim2), sev, rr1);
            }
        }
    }

    // ==================== XSS + SSTI ====================

    /** @return true 如果检测到任何反射 (XSS 或 SSTI) */
    private boolean probeXSS_SSTI(HttpRequest req, HttpRequestResponse baseRR,
                                HttpParameter param, String baseBody, ScanConfig cfg,
                                String host, String method, String path, boolean isJson) {
        boolean doXss = cfg.xss && !isJson && !baseBody.contains(XSSDetector.MARKER);
        boolean doSsti = cfg.ssti;
        if (!doXss && !doSsti) return false;

        StringBuilder sb = new StringBuilder();
        if (doXss) sb.append(XSSDetector.getCombinedPayload());
        if (doSsti) sb.append(SSTIDetector.getCombinedPayload());
        String payload = sb.toString();

        delay(cfg);
        String pv = param.value();
        HttpRequest modReq = req.withParameter(
                HttpParameter.parameter(param.name(), (pv != null ? pv : "") + payload, param.type()));
        HttpRequestResponse rr = sendProbe(modReq, path, param.name(), payload);

        if (rr==null || rr.response()==null) return false;
        String body = rr.response().bodyToString();
        boolean reported = false;

        if (doXss && !isJsonResponse(rr)) {
            for (String[] f : XSSDetector.analyze(body)) {
                report(host, method, path, param.name(), "XSS", f[0], f[1], f[2], rr);
                reported = true;
            }
        }
        if (doSsti) {
            for (int i=0; i<SSTIDetector.EXPECTED_STRINGS.length; i++) {
                if (body.contains(SSTIDetector.EXPECTED_STRINGS[i])
                        && !baseBody.contains(SSTIDetector.EXPECTED_STRINGS[i])) {
                    String syntax = String.valueOf(SSTIDetector.OPERANDS[i][0])
                            + "*" + SSTIDetector.OPERANDS[i][1];
                    boolean syntaxEchoed = body.contains(syntax);
                    report(host, method, path, param.name(), "SSTI",
                            SSTIDetector.FAMILY_NAMES[i],
                            "Computed " + syntax + "=" + SSTIDetector.EXPECTED_STRINGS[i]
                                    + (syntaxEchoed ? " (syntax also echoed — may be false positive)" : " found"),
                            syntaxEchoed ? "Medium" : "High", rr);
                    reported = true;
                }
            }
        }
        return reported;
    }

    // ==================== NoSQLi ====================

    private boolean probeNoSQLi(HttpRequest req, HttpRequestResponse baseRR,
                                 HttpParameter param, String baseBody, ScanConfig cfg,
                                 String host, String method, String path, String baselineNoSqlErr) {
        boolean found = false;
        String body = req.bodyToString();
        if (body == null) return false;
        for (String[] op : NoSQLiDetector.OPERATOR_PAYLOADS) {
            String mod = NoSQLiDetector.buildOperatorPayload(body, param.name(), op[0]);
            if (mod.equals(body))
                mod = NoSQLiDetector.buildOperatorPayloadNumeric(body, param.name(), op[0]);
            if (mod.equals(body))
                mod = NoSQLiDetector.buildOperatorPayloadAny(body, param.name(), op[0]);
            if (mod.equals(body)) continue;

            delay(cfg);
            HttpRequest modReq = req.withBody(mod);
            HttpRequestResponse rr = sendProbe(modReq, path, param.name(), op[0]);
            if (rr==null) continue;
            String respBody = rr.response().bodyToString();
            double sim = MyCompare.similarity(respBody, baseBody);
            if (sim < cfg.simThresh) {
                report(host, method, path, param.name(), "NoSQLi", op[1],
                        "sim="+MyCompare.fmt(sim), "Medium", rr);
                found = true;
            }
            String err = NoSQLiDetector.detectError(respBody);
            if (err!=null && (baselineNoSqlErr==null || !baselineNoSqlErr.equals(err))) {
                report(host, method, path, param.name(), "NoSQLi", op[1]+" Error",
                        "Pattern: "+err, "High", rr);
                found = true;
            }
        }
        return found;
    }

    // ==================== Logging & Probe ====================

    /** 发送探测请求并记录日志 */
    private HttpRequestResponse sendProbe(HttpRequest modReq, String path,
                                           String paramName, String payload) {
        long t0 = System.currentTimeMillis();
        HttpRequestResponse rr = api.http().sendRequest(modReq);
        long elapsed = System.currentTimeMillis() - t0;

        // ★ 记录到 Logs 标签页
        SwingUtilities.invokeLater(() -> logProbe(modReq, rr, path, paramName, payload, elapsed));

        return rr;
    }

    private void logProbe(HttpRequest modReq, HttpRequestResponse rr,
                           String path, String paramName, String payload, long elapsed) {
        if (logModel == null) return;
        try {
            String time = new SimpleDateFormat("HH:mm:ss").format(new Date());
            String method = modReq.method();
            short code = (rr!=null && rr.response()!=null) ? (short)rr.response().statusCode() : 0;
            int len = (rr!=null && rr.response()!=null && rr.response().body()!=null)
                    ? rr.response().body().length() : 0;

            ProbeLogTableModel.Entry e = new ProbeLogTableModel.Entry(
                    logModel.nextId(), time, method, path,
                    paramName, payload, code, len, elapsed, rr);
            logModel.add(e);
        } catch (Exception ignored) {}
    }

    // ==================== Report ====================

    private void report(String host, String method, String path, String param,
                         String type, String detail, String evidence, String severity,
                         HttpRequestResponse rr) {
        int id = resultCounter.incrementAndGet();
        ScanResult sr = new ScanResult(id, host, method, path, param, type, detail, evidence, severity, rr);
        SwingUtilities.invokeLater(() -> { if (tableModel!=null) tableModel.addResult(sr); });
        api.logging().logToOutput("[xia_tan] "+severity+" | "+type+" | "+detail
                +" | "+host+path+" | "+param);
    }

    // ==================== Filters & Helpers ====================

    /** Header 注入专用体量异常检测 (不依赖 ThreadLocal，静态计算) */
    private static boolean isHeaderProbeDiffPage(String base, String probe) {
        if (base == null || probe == null) return false;
        int bl = base.length(), pl = probe.length();
        if (bl == 0 && pl == 0) return false;
        if (bl == 0 || pl == 0) return true;
        double r = (double) pl / bl;
        if (r < 0.10 || r > 10.0) return true;
        if (bl >= 3000 && pl < 500) return true;
        return false;
    }

    private boolean isStatic(String path) {
        // 剥离 query string，避免 style.css?v=111 绕过静态检测
        if (path != null) {
            int q = path.indexOf('?');
            if (q >= 0) path = path.substring(0, q);
        }
        String l = path != null ? path.toLowerCase() : "";
        for (String e : STATIC_EXTS) if (l.endsWith(e)) return true;
        return false;
    }

    private boolean isCudBlocked(String path, ScanConfig cfg) {
        if (!cfg.scanAdd && matches(path, ADD_KW)) return true;
        if (!cfg.scanDel && matches(path, DEL_KW)) return true;
        if (!cfg.scanMod && matches(path, MOD_KW)) return true;
        return false;
    }

    private boolean matches(String p, String[] kws) {
        // 剥离 query string，避免 /api/delete?id=1 中 "delete?id=1" 无法匹配 "delete"
        int qi = p.indexOf('?');
        if (qi >= 0) p = p.substring(0, qi);
        for (String seg:p.split("/")) {
            String l=seg.toLowerCase();
            for (String kw:kws) {
                if (l.equals(kw)) return true;
                if (l.startsWith(kw) && kw.length()<seg.length()) {
                    char n=seg.charAt(kw.length());
                    if (Character.isUpperCase(n)||n=='_'||n=='-'||n=='.') return true;
                }
            }
        }
        return false;
    }

    private String contentType(HttpRequestResponse rr) {
        try {
            String ct = rr.response().headerValue("Content-Type");
            if (ct!=null) return ct.split(";")[0].trim().toLowerCase();
        } catch (Exception ignored) {}
        return null;
    }

    private boolean isBinary(String ct) {
        return ct!=null && (ct.startsWith("image/")||ct.startsWith("audio/")
                ||ct.startsWith("video/")||ct.equals("application/octet-stream")
                ||ct.equals("application/pdf")||ct.equals("application/zip"));
    }

    private boolean isJsonResponse(HttpRequestResponse rr) {
        String ct=contentType(rr);
        return ct!=null && ct.contains("json");
    }

    /** 计算请求体 SHA-256 哈希（内容去重） */
    private String hashRequestBody(HttpRequest req) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            String content = req.method() + req.path() + req.bodyToString();
            byte[] hash = md.digest(content.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString().substring(0, 16);
        } catch (Exception e) { return UUID.randomUUID().toString(); }
    }

    /** 提取 Cookie 参数（仅当 Cookie 开关打开时调用） */
    private List<HttpParameter> extractCookieParams(HttpRequest req) {
        List<HttpParameter> list = new ArrayList<>();
        String cookieHeader = req.headerValue("Cookie");
        if (cookieHeader == null) return list;
        for (String pair : cookieHeader.split(";")) {
            int eq = pair.indexOf("=");
            if (eq <= 0) continue;
            String name = pair.substring(0, eq).trim();
            String value = eq + 1 < pair.length() ? pair.substring(eq + 1).trim() : "";
            list.add(HttpParameter.parameter(name, value, HttpParameterType.COOKIE));
        }
        return list;
    }

    /** @return true 如果检测到 SQLi (调用方可跳过后继参数) */
    private boolean scanWithEncoding(HttpRequest req, HttpRequestResponse baseRR,
                                   HttpParameter param, String baseBody, ScanConfig cfg,
                                   String host, String method, String path,
                                   String respCt, boolean isJsonReq,
                                   String baselineSqlErr, String baselineNoSqlErr,
                                   Set<String> excl) {
        EncodingDetector.Result enc = EncodingDetector.detect(param.value());
        HttpParameter probeParam = param;

        if (enc.type != EncodingDetector.Type.NONE) {
            for (AbstractInjectionStrategy s : sqliStrategies) s.setCookieEncoding(enc.type);
            timeBased.setCookieEncoding(enc.type);
            probeParam = HttpParameter.parameter(param.name(), enc.decoded, param.type());
        }

        boolean sqliHit = scanOneParam(req, baseRR, probeParam, baseBody, cfg, host, method, path, respCt, isJsonReq, baselineSqlErr, baselineNoSqlErr, excl);

        for (AbstractInjectionStrategy s : sqliStrategies) s.setCookieEncoding(EncodingDetector.Type.NONE);
        timeBased.setCookieEncoding(EncodingDetector.Type.NONE);
        return sqliHit;
    }

    /** @return true 如果检测到 SQLi */
    private boolean scanOneParam(HttpRequest req, HttpRequestResponse baseRR,
                               HttpParameter param, String baseBody, ScanConfig cfg,
                               String host, String method, String path,
                               String respCt, boolean isJsonReq,
                               String baselineSqlErr, String baselineNoSqlErr,
                               Set<String> excl) {
        boolean sqliHit = false;
        try {
            // XSS Phase 1：HTML 标签反射 + SSTI 合并探针
            boolean phase1Reflected = false;
            if (cfg.xss || cfg.ssti) {
                phase1Reflected = probeXSS_SSTI(req, baseRR, param, baseBody, cfg, host, method, path,
                        respCt != null && respCt.contains("json"));
            }

            // XSS Phase 2：事件注入 / 属性注入 / JS 上下文
            // 仅当 Phase 1 检测到任何反射时才执行（减少无效探测）
            if (cfg.xss && phase1Reflected && respCt != null && !respCt.contains("json")) {
                for (String[] probe : XSSDetector.ADVANCED_PROBES) {
                    delay(cfg);
                    String pv2 = param.value();
                    HttpRequest modReq = req.withParameter(
                            HttpParameter.parameter(param.name(), (pv2 != null ? pv2 : "") + probe[0], param.type()));
                    HttpRequestResponse rr = sendProbe(modReq, path, param.name(), probe[0]);
                    if (rr == null || rr.response() == null) continue;
                    String body = rr.response().bodyToString();
                    for (String[] f : XSSDetector.analyzeEvent(body)) {
                        report(host, method, path, param.name(), "XSS", f[0], f[1], f[2], rr);
                    }
                    for (String[] f : XSSDetector.analyzeJS(body)) {
                        report(host, method, path, param.name(), "XSS", f[0], f[1], f[2], rr);
                    }
                }
            }

            // SQLi 策略链：链内命中即停（避免同类型重复探测）
            if (cfg.sqli) {
                for (AbstractInjectionStrategy strat : sqliStrategies) {
                    strat.setSimThreshold(cfg.simThresh);
                    strat.setWafBypass(cfg.wafBypass);
                    delay(cfg);
                    HttpRequestResponse probeRR = strat.execute(req, baseRR, param, baseBody);
                    if (probeRR != null) {
                        String sev = "High";
                        // UnifiedString 盲注无 DB 报错时降级为 Medium
                        if (strat instanceof UnifiedStringInjection) {
                            String err = ErrorBasedInjection.detectError(
                                    probeRR.response() != null ? probeRR.response().bodyToString() : "");
                            if (err == null || (baselineSqlErr != null && baselineSqlErr.equals(err)))
                                sev = "Medium";
                        }
                        report(host, method, path, param.name(), "SQLi",
                                strat.getVulnType(), strat.getPayload(), sev, probeRR);
                        sqliHit = true;
                        break;
                    }
                }
            }

            // 延时注入：独立于 SQLi 链
            if (cfg.sqli && cfg.timeSqli) {
                timeBased.setTimeThreshold(cfg.timeThresh);
                timeBased.setWafBypass(cfg.wafBypass);
                HttpRequestResponse probeRR = timeBased.execute(req, baseRR, param, baseBody);
                if (probeRR != null) {
                    report(host, method, path, param.name(), "SQLi",
                            timeBased.getVulnType(), timeBased.getPayload(), "High", probeRR);
                    sqliHit = true;
                }
            }

            // NoSQLi：仅 JSON 请求体
            if (cfg.nosqli && isJsonReq) {
                probeNoSQLi(req, baseRR, param, baseBody, cfg, host, method, path, baselineNoSqlErr);
            }
        } catch (Exception e) {
            api.logging().logToOutput("[xia_tan] error: " + param.name() + " - " + e.getMessage());
        }
        return sqliHit;
    }

    private Set<String> parseSet(String csv) {
        Set<String> s=new HashSet<>();
        if (csv!=null) for (String t:csv.split(",")) {
            String v=t.trim().toLowerCase(); if (!v.isEmpty()) s.add(v);
        }
        return s;
    }

    private void delay(ScanConfig cfg) {
        if (cfg.delay>0) try{Thread.sleep(cfg.delay);}catch(InterruptedException ignored){}
    }
}
