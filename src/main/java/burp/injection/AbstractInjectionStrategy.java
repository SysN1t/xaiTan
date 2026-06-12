package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.util.EncodingDetector;
import java.util.Base64;

public abstract class AbstractInjectionStrategy {

    protected final MontoyaApi api;
    // Cookie 编码上下文 — ThreadLocal 避免多线程竞争
    private final ThreadLocal<EncodingDetector.Type> cookieEncoding =
            ThreadLocal.withInitial(() -> EncodingDetector.Type.NONE);
    // 相似度阈值 — ThreadLocal 支持并发扫描各自使用不同阈值
    private final ThreadLocal<Double> simThreshold =
            ThreadLocal.withInitial(() -> 0.9);
    // WAF 绕过开关 — ThreadLocal
    private final ThreadLocal<Boolean> wafBypass =
            ThreadLocal.withInitial(() -> true);
    // ErrorBased 共享的 ' 探针响应 — 避免 UnifiedString 重复发送
    // static: 同线程上不同策略实例共享同一个 ThreadLocal
    private static final ThreadLocal<HttpRequestResponse> sharedSingleQuoteProbe =
            ThreadLocal.withInitial(() -> null);

    protected AbstractInjectionStrategy(MontoyaApi api) { this.api = api; }

    public abstract String getName();
    public abstract String getVulnType();
    public abstract String getPayload();

    /** 设置 Cookie 编码类型（调用 execute 前由 ScanEngine 设置，结束后清除） */
    public void setCookieEncoding(EncodingDetector.Type type) { cookieEncoding.set(type); }
    /** 设置相似度阈值 */
    public void setSimThreshold(double t) { simThreshold.set(t); }
    /** 设置 WAF 绕过开关 */
    public void setWafBypass(boolean enabled) { wafBypass.set(enabled); }
    /** 设置共享的 ' 探针响应 (ErrorBased → UnifiedString) */
    public void setSingleQuoteProbe(HttpRequestResponse rr) { sharedSingleQuoteProbe.set(rr); }

    /** 获取当前线程的相似度阈值 */
    protected double sim() { return simThreshold.get(); }
    /** 获取共享的 ' 探针响应 */
    protected HttpRequestResponse getSingleQuoteProbe() { return sharedSingleQuoteProbe.get(); }

    /** 判断探针响应是否来自不同页面（体量异常 → 路由变化而非 SQLi）
     *  双层检查：
     *  ① 体量比：探针 <10% 或 >1000% 基线 → 不同页面
     *  ② 绝对体积：基线 ≥3KB 但探针 <500B → 错误页/重定向（补 ratio 在小响应上的盲区）
     *  ③ 空 body：一方有内容一方为空 → 不同页面（重定向）
     */
    protected boolean isDifferentPage(String baseBody, String probeBody) {
        if (baseBody == null || probeBody == null) return false;
        int baseLen = baseBody.length();
        int probeLen = probeBody.length();
        // 双方都空 → 相同（都是重定向）
        if (baseLen == 0 && probeLen == 0) return false;
        // 一方空 → 不同页面（重定向 vs 正常页）
        if (baseLen == 0 || probeLen == 0) return true;
        // 体量比极端异常
        double ratio = (double) probeLen / baseLen;
        if (ratio < 0.10 || ratio > 10.0) return true;
        // 绝对体积异常：基线 ≥3KB 但探针 <500B → 错误页
        if (baseLen >= 3000 && probeLen < 500) return true;
        return false;
    }

    public abstract HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                                  HttpParameter param, String baseBody);

    protected HttpRequestResponse send(HttpRequest req) {
        return api.http().sendRequest(req);
    }

    protected String body(HttpRequestResponse rr) {
        return rr!=null && rr.response()!=null ? rr.response().bodyToString() : "";
    }

    protected HttpRequest modParam(HttpRequest orig, HttpParameter param, String newVal) {
        EncodingDetector.Type enc = cookieEncoding.get();
        if (enc != EncodingDetector.Type.NONE) {
            newVal = EncodingDetector.encodePayload(enc, "", newVal);
        }
        return orig.withParameter(HttpParameter.parameter(param.name(), newVal, param.type()));
    }

    protected HttpRequest append(HttpRequest orig, HttpParameter param, String payload) {
        String base = param.value();
        String p = wafBypass.get() ? burp.util.WafBypass.apply(payload) : payload;
        String value = (base != null ? base : "") + p;
        // URL/Body 参数空格编码为 %20 (Cookie 不编码)
        if (param.type() != HttpParameterType.COOKIE) {
            value = value.replace(" ", "%20");
        }
        return modParam(orig, param, value);
    }

    /** 替换参数值（不拼接原值） */
    protected HttpRequest replace(HttpRequest orig, HttpParameter param, String newVal) {
        String p = wafBypass.get() ? burp.util.WafBypass.apply(newVal) : newVal;
        if (param.type() != HttpParameterType.COOKIE) {
            p = p.replace(" ", "%20");
        }
        return modParam(orig, param, p);
    }
}
