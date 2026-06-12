package burp.util;

import java.util.Base64;
import java.io.UnsupportedEncodingException;

/**
 * Cookie 编码检测器 — 自动识别 base64/URL/Hex 编码并解码
 */
public class EncodingDetector {

    public enum Type { NONE, BASE64, URL, HEX }

    /** 检测编码类型并返回解码后的值 */
    public static Result detect(String value) {
        if (value == null || value.isEmpty()) return new Result(Type.NONE, value);

        // 1. Base64 检测：≥12字符 + 4的倍数 + 解码后≥8字节（降低短随机串误判）
        if (value.matches("^[A-Za-z0-9+/]+=*$") && value.length() >= 12 && value.length() % 4 == 0) {
            try {
                byte[] decoded = Base64.getDecoder().decode(value);
                if (decoded.length < 8) throw new IllegalArgumentException("too short");
                String text = new String(decoded, "UTF-8");
                if (text.matches("^[\\x20-\\x7E]+$")) {
                    return new Result(Type.BASE64, text);
                }
            } catch (IllegalArgumentException | UnsupportedEncodingException ignored) {}
        }

        // 2. URL 编码检测：含 %XX 模式
        if (value.contains("%") && value.matches(".*%[0-9A-Fa-f]{2}.*")) {
            try {
                String decoded = java.net.URLDecoder.decode(value, "UTF-8");
                if (!decoded.equals(value)) {
                    return new Result(Type.URL, decoded);
                }
            } catch (Exception ignored) {}
        }

        // 3. Hex 编码检测：≥8字符 + 偶数长度纯 hex（降低短 hex 值误判）
        if (value.length() >= 8 && value.length() % 2 == 0 && value.matches("^[0-9A-Fa-f]+$")) {
            try {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < value.length(); i += 2) {
                    int c = Integer.parseInt(value.substring(i, i + 2), 16);
                    sb.append((char) c);
                }
                String decoded = sb.toString();
                if (decoded.matches("^[\\x20-\\x7E]+$")) {
                    return new Result(Type.HEX, decoded);
                }
            } catch (Exception ignored) {}
        }

        return new Result(Type.NONE, value);
    }

    /** 将 payload 按照指定编码方式编码后与原值拼接 */
    public static String encodePayload(Type type, String originalValue, String payload) {
        String combined = originalValue + payload;
        switch (type) {
            case BASE64: try { return Base64.getEncoder().encodeToString(combined.getBytes("UTF-8")); } catch (java.io.UnsupportedEncodingException e) { return combined; }
            case URL:    try { return java.net.URLEncoder.encode(combined, "UTF-8"); } catch (Exception e) { return combined; }
            case HEX: {
                StringBuilder sb = new StringBuilder();
                try {
                    for (byte b : combined.getBytes("UTF-8")) sb.append(String.format("%02X", b));
                } catch (java.io.UnsupportedEncodingException e) {
                    return combined; // fallback: return unencoded
                }
                return sb.toString();
            }
            default: return combined;
        }
    }

    public static class Result {
        public final Type type;
        public final String decoded;
        Result(Type t, String d) { this.type = t; this.decoded = d; }
    }
}
