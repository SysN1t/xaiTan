package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;
import java.util.*;

public class OrderByInjection extends AbstractInjectionStrategy {

    private static final Set<String> NAMES = new HashSet<>(Arrays.asList(
        "sort","order","orderby","order_by","sortby","sort_by",
        "sortfield","sort_field","sortcolumn","sort_column",
        "column","col","field","dir","direction","sort_dir","sort_order"
    ));
    private String lastPayload = "";

    public OrderByInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Order-By";}
    @Override public String getVulnType(){return"ordersql";}
    @Override public String getPayload(){return lastPayload;}

    public static boolean isOrderParam(String name){return name!=null && NAMES.contains(name.toLowerCase());}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // 对所有参数测试 ORDER BY（参数名不限，相似度逻辑自行过滤非排序参数）

        lastPayload = ",0";
        HttpRequestResponse rr1 = send(append(origReq, param, lastPayload));
        if(rr1==null) return null;
        if(MyCompare.similarity(baseBody, body(rr1)) >= 0.9) return null;

        lastPayload = ",xxxxxx";
        HttpRequestResponse rr2 = send(append(origReq, param, lastPayload));
        if(rr2==null) return null;
        if(MyCompare.similarity(baseBody, body(rr2)) >= 0.9) return null;

        lastPayload = ",1";
        HttpRequestResponse rr3 = send(append(origReq, param, lastPayload));
        if(rr3==null) return null;
        if(MyCompare.similarity(baseBody, body(rr3)) >= 0.9) return rr3;

        lastPayload = ",2";
        HttpRequestResponse rr4 = send(append(origReq, param, lastPayload));
        if(rr4==null) return null;
        return MyCompare.similarity(baseBody, body(rr4)) >= 0.9 ? rr4 : null;
    }
}
