package burp.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.util.MyCompare;
import java.util.*;
import java.util.regex.Pattern;

public class ErrorBasedInjection extends AbstractInjectionStrategy {

    private static final String[] PROBES = {"'", "\"", "\\", "'\"\\"};
    private static final Map<String, Pattern[]> DB = new LinkedHashMap<>();
    static {
        DB.put("MySQL", arr("SQL syntax.*?MySQL","MySQLSyntaxErrorException","Warning.*?\\bmysql_",
            "check the manual.*MySQL|MariaDB","Unknown column '[^']+' in","mysql_fetch|mysql_num_rows",
            "MySqlException","SQLSTATE\\[HY","com\\.mysql\\.jdbc","XPATH syntax error"));
        DB.put("MSSQL", arr("Microsoft.*?ODBC.*?Driver","Unclosed quotation mark",
            "Incorrect syntax near","SqlException","System\\.Data\\.SqlClient"));
        DB.put("PostgreSQL", arr("PostgreSQL.*?ERROR","PG::SyntaxError","ERROR:\\s+syntax error at or near",
            "unterminated quoted string"));
        DB.put("Oracle", arr("ORA-[0-9]{4,5}","Oracle.*?Driver"));
        DB.put("SQLite", arr("SQLite.*?Exception","SQLITE_ERROR","unrecognized token"));
    }
    private static Pattern[] arr(String...rs){return Arrays.stream(rs).map(r->Pattern.compile(r,Pattern.CASE_INSENSITIVE)).toArray(Pattern[]::new);}

    public static String detectError(String body){
        for(Map.Entry<String,Pattern[]> e:DB.entrySet())
            for(Pattern p:e.getValue()) if(p.matcher(body).find()) return e.getKey();
        return null;
    }

    private String lastPayload = "";

    public ErrorBasedInjection(MontoyaApi api){super(api);}
    @Override public String getName(){return"Error-Based";}
    @Override public String getVulnType(){return"errsql";}
    @Override public String getPayload(){return lastPayload;}

    @Override
    public HttpRequestResponse execute(HttpRequest origReq, HttpRequestResponse baseRR,
                                         HttpParameter param, String baseBody){
        for(String probe:PROBES){
            lastPayload = probe;
            HttpRequest modReq = append(origReq, param, probe);
            HttpRequestResponse rr = send(modReq);
            if(rr==null) continue;
            String err = detectError(body(rr));
            if(err!=null){
                String baseErr = detectError(baseBody);
                if(baseErr==null || !baseErr.equals(err)) return rr;
            }
        }
        return null;
    }
}
