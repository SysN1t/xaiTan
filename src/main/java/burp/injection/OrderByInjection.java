package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class OrderByInjection extends AbstractInjectionStrategy {

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");

    public OrderByInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Order-By";}
    @Override public String getVulnType(){return"ordersql";}
    @Override public String getPayload(){return lastPayload.get();}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // 对所有参数测试 ORDER BY（参数名不限，相似度逻辑自行过滤非排序参数）

        lastPayload.set(",0");
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload.get()));
        if(rr1==null) return null;
        if(MyCompare.similarity(baseBody, body(rr1)) >= sim()) return null;

        lastPayload.set(",xxxxxx");
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload.get()));
        if(rr2==null) return null;
        String body2 = body(rr2);
        if(MyCompare.similarity(baseBody, body2) >= sim()) return null;

        // 交叉验证：两个错误探针应产生相似的错误页（DetSql 做法）
        String bodyErr1 = body(rr1);
        if(MyCompare.similarity(bodyErr1, body2) < sim()) return null;

        // Step 4a: ,1 — 期望与基线相似（有效列索引），且与错误探针不相似
        lastPayload.set(",1");
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload.get()));
        if(rr3==null) return null;
        String body3 = body(rr3);
        if(MyCompare.similarity(baseBody, body3) >= sim()
                && MyCompare.similarity(bodyErr1, body3) < sim()) return rr3;

        // Step 4b: ,2 — 备选有效列索引
        lastPayload.set(",2");
        HttpRequestResponse rr4 = send(append(origReq, param, lastPayload.get()));
        if(rr4==null) return null;
        String body4 = body(rr4);
        return (MyCompare.similarity(baseBody, body4) >= sim()
                && MyCompare.similarity(bodyErr1, body4) < sim()) ? rr4 : null;
    }
}
