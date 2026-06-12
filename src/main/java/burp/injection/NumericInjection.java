package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class NumericInjection extends AbstractInjectionStrategy {

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");

    public NumericInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Numeric";}
    @Override public String getVulnType(){return"numsql";}
    @Override public String getPayload(){return lastPayload.get();}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        String val = param.value();
        if(val==null || !val.matches("^-?\\d+(\\.\\d+)?")) return null;

        // Phase 1: 追加算术 (保持原值上下文)
        lastPayload.set("-0-0-0");
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload.get()));
        if(rr1!=null && !isDifferentPage(baseBody, body(rr1))
                && MyCompare.similarity(baseBody, body(rr1)) >= sim()) {

            lastPayload.set("-abc");
            HttpRequestResponse rr2 = send(append(origReq, param, lastPayload.get()));
            if(rr2!=null && !isDifferentPage(baseBody, body(rr2))
                    && MyCompare.similarity(baseBody, body(rr2)) < sim()
                    && MyCompare.similarity(body(rr1), body(rr2)) < sim()) {
                return rr2;
            }
        }

        // Phase 2: 替换为除法 (独立于 Phase 1)
        lastPayload.set("1/0");
        HttpRequestResponse rr3 = send(replace(origReq, param, lastPayload.get()));
        if (rr3 != null && !isDifferentPage(baseBody, body(rr3))
                && MyCompare.similarity(baseBody, body(rr3)) < sim()) {

            lastPayload.set("1/1");
            HttpRequestResponse rr4 = send(replace(origReq, param, lastPayload.get()));
            if (rr4 != null && !isDifferentPage(baseBody, body(rr4))
                    && MyCompare.similarity(body(rr3), body(rr4)) < sim()) {
                return rr3;
            }
        }

        return null;
    }
}
