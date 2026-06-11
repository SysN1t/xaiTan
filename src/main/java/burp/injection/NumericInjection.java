package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class NumericInjection extends AbstractInjectionStrategy {

    private String lastPayload = "";

    public NumericInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Numeric";}
    @Override public String getVulnType(){return"numsql";}
    @Override public String getPayload(){return lastPayload;}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        String val = param.value();
        if(val==null || !val.matches("^-?\\d+(\\.\\d+)?")) return null;

        lastPayload = "-0-0-0";
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload));
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(MyCompare.similarity(baseBody, body1) < 0.9) return null;

        lastPayload = "-abc";
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload));
        if(rr2==null) return null;
        String body2 = body(rr2);
        if(MyCompare.similarity(baseBody, body2) >= 0.9) return null;
        if(MyCompare.similarity(body1, body2) >= 0.9) return null;

        // 第三步确认：-0 等价变换应与基线相同（排除输入校验导致的误报）
        lastPayload = "-0";
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload));
        if(rr3 != null && MyCompare.similarity(baseBody, body(rr3)) >= 0.9) return rr2;
        return null;
    }
}
