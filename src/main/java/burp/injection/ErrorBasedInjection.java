package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import java.util.*;
import java.util.regex.Pattern;

public class ErrorBasedInjection extends AbstractInjectionStrategy {

    // 基础报错探针 — 最少覆盖（' / " 覆盖 95%+，') 覆盖括号闭合场景）
    // 已移除: \（MySQL 宽字节由增强探针 %DF' 覆盖）
    //         ')) / ")（多层括号闭合极罕见，且 ErrorBased 命中即停无需穷举）
    private static final String[] PROBES = { "'", "\"", "')" };

    // 可选增强探针 — 默认关闭 (宽字节/反引号等边缘场景)
    private static final String[] PROBES_EXTENDED = {
        "'\"\\", "`", "%DF'", "%DF\""
    };

    /** 是否启用增强探针 (外部可配置) */
    public static boolean extendedProbes = false;

    // 10 种数据库错误特征（完整版，继承原版 xia_tan v1.0）
    private static final Map<String, Pattern[]> DB = new LinkedHashMap<>();
    static {
        DB.put("MySQL", arr(
            "SQL syntax.*?MySQL","MySQLSyntaxErrorException","Warning.*?\\bmysql_",
            "check the manual.*(MySQL|MariaDB)","Unknown column '[^']+' in",
            "mysql_fetch|mysql_num_rows","MySqlException","SQLSTATE\\[HY",
            "com\\.mysql\\.jdbc","XPATH syntax error","Operand should contain \\d column",
            "Duplicate entry '.*' for key","Data truncated for column"
        ));
        DB.put("MSSQL", arr(
            "Microsoft.*?ODBC.*?Driver","Unclosed quotation mark",
            "Microsoft.*?SQL.*?Server","Incorrect syntax near",
            "SqlException","System\\.Data\\.SqlClient","mssql_query",
            "Procedure '[^']+' expects parameter","ODBC SQL Server Driver",
            "Arithmetic overflow error"
        ));
        DB.put("PostgreSQL", arr(
            "PostgreSQL.*?ERROR","PG::SyntaxError","ERROR:\\s+syntax error at or near",
            "unterminated quoted string","current transaction is aborted",
            "org\\.postgresql","Npgsql\\."
        ));
        DB.put("Oracle", arr(
            "ORA-[0-9]{4,5}","Oracle.*?Driver","Warning.*?\\boci_","Warning.*?\\bora_",
            "oracle\\.jdbc","quoted string not properly terminated","SQL command not properly ended"
        ));
        DB.put("SQLite", arr(
            "SQLite.*?Exception","SQLITE_ERROR","\\[SQLITE_ERROR\\]","unrecognized token",
            "System\\.Data\\.SQLite","near \"[^\"]*\": syntax error"
        ));
        DB.put("DB2", arr("CLI Driver.*?DB2","DB2 SQL error","\\bdb2_\\w+\\(","SQLCODE[=\\s]","com\\.ibm\\.db2"));
        DB.put("Informix", arr("Warning.*?\\bibase_","com\\.informix\\.jdbc","SQLCODE=-"));
        DB.put("Sybase", arr("Warning.*?\\bsybase","Sybase.*?message","Adaptive Server"));
        DB.put("MS Access", arr("Microsoft Access.*?Driver","JET Database Engine","Access Database Engine"));
        DB.put("HQL/Hibernate", arr("org\\.hibernate\\.QueryException","org\\.hibernate\\.exception","javax\\.persistence","HqlToken"));
    }

    private static Pattern[] arr(String...rs){return Arrays.stream(rs).map(r->Pattern.compile(r,Pattern.CASE_INSENSITIVE)).toArray(Pattern[]::new);}

    /** 返回匹配的数据库类型（用于报告） */
    public static String detectErrorDB(String body){
        for(Map.Entry<String,Pattern[]> e:DB.entrySet())
            for(Pattern p:e.getValue()) if(p.matcher(body).find()) return e.getKey();
        return null;
    }

    /** 返回匹配的具体错误模式（用于基线精确比较） */
    public static String detectError(String body){
        for(Map.Entry<String,Pattern[]> e:DB.entrySet())
            for(Pattern p:e.getValue()) if(p.matcher(body).find()) return p.pattern();
        return null;
    }

    private final ThreadLocal<String> lastPayload = ThreadLocal.withInitial(() -> "");
    private final ThreadLocal<String> baselineSqlErr = ThreadLocal.withInitial(() -> null);

    public ErrorBasedInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Error-Based";}
    @Override public String getVulnType(){return"errsql";}
    @Override public String getPayload(){return lastPayload.get();}

    /** 由 ScanEngine 注入基线错误模式，避免 execute() 内重复扫描 10 种 DB 正则 */
    public void setBaselineSqlErr(String err) { baselineSqlErr.set(err); }

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        // 使用 ScanEngine 注入的基线错误模式（避免重复正则扫描）
        String baseErr = baselineSqlErr.get();
        short baseCode = statusCode(baseRR);

        // Phase 1: 基础报错探针
        for (int i = 0; i < PROBES.length; i++) {
            String probe = PROBES[i];
            lastPayload.set(probe);
            HttpRequest modReq = append(origReq, param, probe);
            HttpRequestResponse rr = send(modReq);
            if (rr == null) continue;
            // 共享 ' 探针响应给 UnifiedString 复用
            if (i == 0) setSingleQuoteProbe(rr);
            String probeBody = body(rr);
            if (isDifferentPage(baseBody, probeBody, baseCode, statusCode(rr))) continue;
            String err = detectError(probeBody);
            if (err != null && (baseErr == null || !baseErr.equals(err))) return rr;
        }

        // Phase 1b: 可选增强探针 (宽字节/反引号等边缘场景)
        if (extendedProbes) {
            for (String probe : PROBES_EXTENDED) {
                lastPayload.set(probe);
                HttpRequest modReq = append(origReq, param, probe);
                HttpRequestResponse rr = send(modReq);
                if (rr == null) continue;
                String probeBody = body(rr);
                if (isDifferentPage(baseBody, probeBody, baseCode, statusCode(rr))) continue;
                String err = detectError(probeBody);
                if (err != null && (baseErr == null || !baseErr.equals(err))) return rr;
            }
        }

        return null;
    }
}
