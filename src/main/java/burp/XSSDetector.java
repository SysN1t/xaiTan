package burp;

import java.util.*;

public class XSSDetector {

    public static final String MARKER = "xia0tan";

    // 4 种 XSS payload — 覆盖不同注入上下文
    public static final String HTML_PAYLOAD   = "<" + MARKER + ">";
    public static final String EVENT_PAYLOAD  = "\">" + HTML_PAYLOAD;
    public static final String ATTR_PAYLOAD   = "\" onmouseover=\"" + MARKER + "\" x=\"";
    public static final String JS_PAYLOAD     = "'-" + MARKER + "-'";

    /** Phase 1 合并探针用（与 SSTI 拼在一起发送） */
    public static String getCombinedPayload() {
        return HTML_PAYLOAD;
    }

    /** Phase 1 结果分析：HTML 标签反射 */
    public static List<String[]> analyze(String body) {
        List<String[]> f = new ArrayList<>();
        if (body.contains(HTML_PAYLOAD)) {
            f.add(new String[]{"Reflected (Unencoded)",
                    "HTML tag <" + MARKER + "> reflected without encoding", "High"});
        } else if (body.contains(MARKER)) {
            // 仅在 HTML 上下文中出现才报 Info（排除纯文本错误页面的巧合匹配）
            if (body.contains("&lt;" + MARKER + "&gt;")
                    || body.contains("&lt;xia0tan&gt;")
                    || body.contains("value=\"" + MARKER + "\"")
                    || body.contains(">" + MARKER + "<")) {
                f.add(new String[]{"Reflected (Encoded)",
                        "Marker '" + MARKER + "' reflected (HTML-encoded)", "Info"});
            }
        }
        return f;
    }

    /** Phase 2 探针列表（事件注入 + JS 上下文） */
    public static final String[][] ADVANCED_PROBES = {
        {EVENT_PAYLOAD, "Event Injection"},
        {ATTR_PAYLOAD,  "Attribute Injection"},
        {JS_PAYLOAD,    "JS Context Reflection"},
    };

    /** 分析事件注入结果 */
    public static List<String[]> analyzeEvent(String body) {
        List<String[]> f = new ArrayList<>();
        if (body.contains("onmouseover=\"" + MARKER + "\"")) {
            f.add(new String[]{"Event Injection",
                    "Event handler attribute injected", "High"});
        }
        return f;
    }

    /** 分析 JS 上下文反射结果 */
    public static List<String[]> analyzeJS(String body) {
        List<String[]> f = new ArrayList<>();
        if (body.contains("'-" + MARKER + "-'")) {
            f.add(new String[]{"JS Context Reflection",
                    "Payload reflected in JS string context", "High"});
        }
        return f;
    }
}
