package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
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

    protected AbstractInjectionStrategy(MontoyaApi api) { this.api = api; }

    public abstract String getName();
    public abstract String getVulnType();
    public abstract String getPayload();

    /** 设置 Cookie 编码类型（调用 execute 前由 ScanEngine 设置，结束后清除） */
    public void setCookieEncoding(EncodingDetector.Type type) { cookieEncoding.set(type); }

    /** 设置相似度阈值（调用 execute 前由 ScanEngine 设置） */
    public void setSimThreshold(double t) { simThreshold.set(t); }

    /** 获取当前线程的相似度阈值 */
    protected double sim() { return simThreshold.get(); }

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
        return modParam(orig, param, (base != null ? base : "") + payload);
    }
}
