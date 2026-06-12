package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

/**
 * 统一字符串/布尔盲注策略 — 合并 StringInjection + BooleanBlind
 * 复用 ErrorBased 的 ' 探针响应，减少重复请求
 *
 * Step 0: ' 探针已由 ErrorBased 发送，复用其响应做预检
 * Step 1: '' — 双引号修复语法 → 命中 = 字符串注入确认
 * Step 2: ' AND 1=1-- — true 条件 → 建立参考体
 * Step 3: ' AND 1=2-- — false 条件 → 确认布尔盲注
 * Fallback: '||'||' — Oracle/PostgreSQL 风格拼接 (1=1/1=2 失败时尝试)
 */
public class UnifiedStringInjection extends AbstractInjectionStrategy {

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");

    public UnifiedStringInjection(MontoyaApi api) { super(api); }
    @Override public String getName() { return "Unified-String"; }
    @Override public String getVulnType() { return "stringsql"; }
    @Override public String getPayload() { return lastPayload.get(); }

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody) {
        // Step 0: 优先复用 ErrorBased 的 ' 探针响应；为 null 时自行发送（防御性 fallback）
        HttpRequestResponse rr0 = getSingleQuoteProbe();
        if (rr0 == null) {
            rr0 = send(append(origReq, param, "'"));
            if (rr0 != null) setSingleQuoteProbe(rr0); // 回写共享，供后续线程复用
        }
        if (rr0 == null) return null;
        short baseCode = statusCode(baseRR);
        String body0 = body(rr0);
        if (MyCompare.similarity(baseBody, body0) >= sim()) return null;
        if (isDifferentPage(baseBody, body0, baseCode, statusCode(rr0))) return null;

        // Step 1: '' — 双引号修复语法 (期望回到基线)
        lastPayload.set("''");
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload.get()));
        if (rr1 == null) return null;
        String body1 = body(rr1);
        if (isDifferentPage(baseBody, body1, baseCode, statusCode(rr1))) return null;

        if (MyCompare.levenshteinStripped(baseBody, body1, null, "''") >= sim()) {
            lastPayload.set("' + ''");
            return rr1; // 字符串注入确认
        }

        // Step 2+3: 1=1 / 1=2 布尔盲注（仅 ' / " 前缀；') / ')) 括号闭合由 ErrorBased 覆盖）
        for (String prefix : new String[]{"'", "\""}) {
            HttpRequestResponse confirmed = tryBoolean(origReq, param, baseBody, prefix, baseCode);
            if (confirmed != null) return confirmed;
        }

        // Fallback: Oracle/PostgreSQL '||' 拼接
        return tryOracleFallback(origReq, param, baseBody, baseCode);
    }

    private HttpRequestResponse tryBoolean(HttpRequest origReq, HttpParameter param,
                                            String baseBody, String prefix, short baseCode) {
        // Step 2: prefix AND 1=1-- (true)
        lastPayload.set(prefix + " AND 1=1-- ");
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload.get()));
        if (rr2 == null || isDifferentPage(baseBody, body(rr2), baseCode, statusCode(rr2))) return null;
        String body2 = body(rr2);

        if (MyCompare.similarity(baseBody, body2) >= sim()) return null;

        // Step 3: prefix AND 1=2-- (false)
        lastPayload.set(prefix + " AND 1=2-- ");
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload.get()));
        if (rr3 == null || isDifferentPage(baseBody, body(rr3), baseCode, statusCode(rr3))) return null;
        String body3 = body(rr3);

        if (MyCompare.levenshteinStripped(body2, body3, "1=1", "1=2") >= sim()) return null;
        if (MyCompare.similarity(baseBody, body3) >= sim()) return null;

        lastPayload.set(prefix + " AND 1=2-- ");
        return rr3;
    }

    private HttpRequestResponse tryOracleFallback(HttpRequest origReq, HttpParameter param,
                                                   String baseBody, short baseCode) {
        lastPayload.set("'||'||'");
        HttpRequestResponse rr = send(append(origReq, param, lastPayload.get()));
        if (rr == null || isDifferentPage(baseBody, body(rr), baseCode, statusCode(rr))) return null;
        if (MyCompare.levenshteinStripped(baseBody, body(rr), null, "'\\|\\|'") >= sim()) {
            return rr;
        }
        return null;
    }
}
