package burp;

import burp.api.montoya.http.message.HttpRequestResponse;

public class ScanResult {
    public final int id;
    public final String host, method, path, paramName, type, detail, evidence, severity;
    public final HttpRequestResponse requestResponse;

    public ScanResult(int id, String host, String method, String path,
                      String paramName, String type, String detail, String evidence,
                      String severity, HttpRequestResponse rr) {
        this.id = id;
        this.host = host;
        this.method = method;
        this.path = path;
        this.paramName = paramName;
        this.type = type;
        this.detail = detail;
        this.evidence = evidence;
        this.severity = severity;
        this.requestResponse = rr;
    }
}
