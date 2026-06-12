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
        // 快速预检：参数值不像列名/列索引则跳过（减少 70-90% 无效探测）
        if (!looksLikeOrderValue(param.value())) return null;

        lastPayload.set(",0");
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload.get()));
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(isDifferentPage(baseBody, body1)) return null;
        if(MyCompare.similarity(baseBody, body1) >= sim()) return null;

        lastPayload.set(",xxxxxx");
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload.get()));
        if(rr2==null) return null;
        String body2 = body(rr2);
        if(isDifferentPage(baseBody, body2)) return null;
        if(MyCompare.similarity(baseBody, body2) >= sim()) return null;

        // 交叉验证：两个错误探针应产生相似的错误页（DetSql 做法）
        if(MyCompare.similarity(body1, body2) < sim()) return null;

        // Step 4a: ,1 — 期望与基线相似（有效列索引），且与错误探针不相似
        lastPayload.set(",1");
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload.get()));
        if(rr3==null) return null;
        String body3 = body(rr3);
        if(isDifferentPage(baseBody, body3)) return null;
        if(MyCompare.similarity(baseBody, body3) >= sim()
                && MyCompare.similarity(body1, body3) < sim()) return rr3;

        return null;
    }

    /** 判断参数值是否像排序字段（纯数字=列索引，纯标识符=列名/方向） */
    private static boolean looksLikeOrderValue(String val) {
        if (val == null || val.isEmpty()) return false;
        return val.matches("^-?\\d+$") || val.matches("^[a-zA-Z_][a-zA-Z0-9_]*$");
    }
}
