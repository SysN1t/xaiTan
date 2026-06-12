package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class StringInjection extends AbstractInjectionStrategy {

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");

    public StringInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"String-Based";}
    @Override public String getVulnType(){return"stringsql";}
    @Override public String getPayload(){return lastPayload.get();}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // Step 1: single quote
        lastPayload.set("'");
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload.get()));
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(MyCompare.similarity(baseBody, body1) >= sim()) return null;

        // Step 2: double quote (compare to step1, not baseline)
        lastPayload.set("''");
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload.get()));
        if(rr2==null) return null;
        String body2 = body(rr2);
        if(MyCompare.levenshteinStripped(body1, body2, "'", "''") >= sim()) return null;

        // Step 3: '+'
        lastPayload.set("'+'");
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload.get()));
        if(rr3==null) return null;
        if(MyCompare.levenshteinStripped(baseBody, body(rr3), null, "'\\+'") >= sim()) return rr3;

        // Step 4: '||' fallback
        lastPayload.set("'||'");
        HttpRequestResponse rr4 = send(append(origReq, param, lastPayload.get()));
        if(rr4==null) return null;
        return MyCompare.levenshteinStripped(baseBody, body(rr4), null, "'\\|\\|'") >= sim() ? rr4 : null;
    }
}
