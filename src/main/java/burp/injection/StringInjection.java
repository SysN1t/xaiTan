package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class StringInjection extends AbstractInjectionStrategy {

    private String lastPayload = "";

    public StringInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"String-Based";}
    @Override public String getVulnType(){return"stringsql";}
    @Override public String getPayload(){return lastPayload;}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // Step 1: single quote
        lastPayload = "'";
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload));
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(MyCompare.similarity(baseBody, body1) >= 0.9) return null;

        // Step 2: double quote (compare to step1, not baseline)
        lastPayload = "''";
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload));
        if(rr2==null) return null;
        String body2 = body(rr2);
        if(MyCompare.levenshteinStripped(body1, body2, "'", "''") >= 0.9) return null;

        // Step 3: '+'
        lastPayload = "'+'";
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload));
        if(rr3==null) return null;
        if(MyCompare.levenshteinStripped(baseBody, body(rr3), null, "'\\+'") >= 0.9) return rr3;

        // Step 4: '||' fallback
        lastPayload = "'||'";
        HttpRequestResponse rr4 = send(append(origReq, param, lastPayload));
        if(rr4==null) return null;
        return MyCompare.levenshteinStripped(baseBody, body(rr4), null, "'\\|\\|'") >= 0.9 ? rr4 : null;
    }
}
