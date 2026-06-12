package burp.util;

import java.util.Random;

/**
 * WAF 绕过载荷变换器 — 对 payload 应用随机等价变换
 * 三种技巧: 大小写随机化 / 注释填充 / 换行替代
 * 25% 概率不转换，确保正常探测不受影响
 */
public class WafBypass {

    private static final Random RNG = new Random();

    /** 对 payload 应用随机 WAF 绕过变换 (不改变 SQL 语义) */
    public static String apply(String payload) {
        if (payload == null || payload.isEmpty()) return payload;
        switch (RNG.nextInt(3)) {
            case 0: return randomCase(payload);
            case 1: return commentSpace(payload);
            default: return newlineSpace(payload);
        }
    }

    /** 随机大小写 SQL 关键词: AND→aNd, OR→oR, SELECT→sElEcT 等 */
    static String randomCase(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetter(c) && RNG.nextBoolean()) {
                sb.append(Character.isUpperCase(c)
                        ? Character.toLowerCase(c)
                        : Character.toUpperCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 用注释符替换部分空格 (不在引号内替换) */
    static String commentSpace(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        boolean inString = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'' && (i == 0 || s.charAt(i - 1) != '\\')) {
                inString = !inString;
                sb.append(c);
            } else if (c == ' ' && !inString && RNG.nextBoolean()) {
                sb.append("/**/");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 用 \\t (Tab) 替换部分空格 — 所有 SQL 数据库认作空白, 无 HTTP 兼容问题 */
    static String newlineSpace(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        boolean inString = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\'' && (i == 0 || s.charAt(i - 1) != '\\')) {
                inString = !inString;
                sb.append(c);
            } else if (c == ' ' && !inString && RNG.nextBoolean()) {
                sb.append('\t');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
