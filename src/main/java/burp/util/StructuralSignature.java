package burp.util;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * 优势 5: REST API 路径结构签名 — 智能去重
 * /user/123      → /user/{int}
 * /api/550e8400-... → /api/{uuid}
 * /session/a1b2c3d4 → /session/{hex}
 */
public class StructuralSignature {

    private static final Pattern UUID_PAT = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern NUM_PAT = Pattern.compile("^\\d+$");
    private static final Pattern HEX_PAT = Pattern.compile("^[0-9a-fA-F]{8,}$");

    /** 噪声参数 (时间戳、随机数等) */
    private static final Set<String> NOISE = new HashSet<>(Arrays.asList(
            "timestamp", "_t", "_ts", "time", "random", "nonce", "_r", "rand", "callback", "jsonp", "_"
    ));

    /**
     * 生成请求的唯一标识签名 (用于去重)
     * @param method HTTP 方法
     * @param path 原始路径
     * @param paramNamesSorted 排序后的参数名列表
     */
    public static String signature(String method, String path, List<String> paramNamesSorted) {
        String sigPath = normalize(path);
        String sigParams = paramNamesSorted.stream()
                .filter(n -> !NOISE.contains(n))
                .sorted()
                .collect(Collectors.joining(","));
        return method + "|" + sigPath + "|" + sigParams;
    }

    /** 规范化路径: 替换动态段为占位符 */
    private static String normalize(String path) {
        if (path == null || path.isEmpty()) return path;

        String[] segments = path.split("/");
        StringBuilder sb = new StringBuilder();

        for (String seg : segments) {
            if (seg.isEmpty()) continue;
            sb.append("/");
            if (NUM_PAT.matcher(seg).matches()) {
                sb.append("{int}");
            } else if (UUID_PAT.matcher(seg).matches()) {
                sb.append("{uuid}");
            } else if (HEX_PAT.matcher(seg).matches()) {
                sb.append("{hex}");
            } else {
                sb.append(seg);
            }
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }
}
