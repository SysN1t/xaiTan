package burp.util;

import java.util.*;

/**
 * 统一响应相似度引擎 — 整合 xia_tan 原有 + DetSql 6 个优势
 *
 * 优势 1: upgradeStr — 剥离公共前后缀 + 删除 POC 痕迹后再比较
 * 优势 2: 长度差辅助判定 — ≤1→100%, ≥100→0%
 * 优势 3: 大响应分段比较 — >50KB 取前10K+后5K均值
 * 优势 4: Levenshtein 快速失败 — 长度差/前缀差异大时提前返回
 * 保留:   Jaccard 行级相似度 (xia_tan 原有)
 */
public class MyCompare {

    private static final int MAX_BODY     = 50 * 1024;   // 50KB
    private static final int HEAD_SIZE    = 10 * 1024;   // 前 10KB
    private static final int TAIL_SIZE    = 5 * 1024;    // 后 5KB
    private static final int LEN_DIFF_MAX = 100;          // 长度差≥100→0.0

    // ==================== 公共 API ====================

    /** 计算两个响应体的综合相似度 (0.0~1.0) */
    public static double similarity(String a, String b) {
        if (a == null && b == null) return 1.0;
        if (a == null || b == null) return 0.0;
        if (a.equals(b)) return 1.0;
        if (a.isEmpty() && b.isEmpty()) return 1.0;
        if (a.isEmpty() || b.isEmpty()) return 0.0;

        // 优势 2: 长度差辅助判定
        int lenDiff = Math.abs(a.length() - b.length());
        if (lenDiff <= 1) return 1.0;
        if (lenDiff >= LEN_DIFF_MAX) return 0.0;

        // 优势 3: 大响应分段比较
        if (a.length() > MAX_BODY || b.length() > MAX_BODY) {
            return segmentedSim(a, b);
        }

        // 默认: Jaccard 行级相似度 (xia_tan 原有)
        return jaccardLineSim(a, b);
    }

    /** Levenshtein 相似度 (带快速失败) */
    public static double levenshtein(String a, String b) {
        return levenshteinImpl(a, b, 0.0);
    }

    /** Levenshtein + 剥离前后缀
     *  pocA 作用于参数 a 的差异部分，pocB 作用于参数 b 的差异部分
     *  (不再按长度分配 POC，避免 StringInjection Step2 等场景的语义错位)
     */
    public static double levenshteinStripped(String a, String b, String pocA, String pocB) {
        String shorter = a.length() <= b.length() ? a : b;
        String longer  = a.length() <= b.length() ? b : a;
        String[] stripped = upgradeStr(shorter, longer);
        if (stripped[0].isEmpty() && stripped[1].isEmpty()) return 1.0;

        // stripped[0]=shorter的差异, stripped[1]=longer的差异
        // 映射回参数 a / b 各自对应的差异部分
        boolean aIsShorter = a.length() <= b.length();
        String diffA = aIsShorter ? stripped[0] : stripped[1];
        String diffB = aIsShorter ? stripped[1] : stripped[0];
        if (pocA != null && !pocA.isEmpty()) diffA = diffA.replaceAll(pocA, "");
        if (pocB != null && !pocB.isEmpty()) diffB = diffB.replaceAll(pocB, "");

        if (diffA.isEmpty() && diffB.isEmpty()) return 1.0;
        if (diffA.isEmpty() || diffB.isEmpty()) return 0.0;

        return levenshtein(diffA, diffB);
    }

    /** 格式化为百分比字符串 */
    public static String fmt(double sim) {
        return String.format("%.1f%%", sim * 100);
    }

    // ==================== 内部实现 ====================

    /** Jaccard 行级相似度 (xia_tan 原有算法) */
    private static double jaccardLineSim(String a, String b) {
        Set<String> setA = toLineSet(a);
        Set<String> setB = toLineSet(b);
        if (setA.isEmpty() && setB.isEmpty()) return 1.0;

        int common = 0;
        for (String s : setA) {
            if (setB.contains(s)) common++;
        }
        int union = setA.size() + setB.size() - common;
        return union > 0 ? (double) common / union : 1.0;
    }

    private static Set<String> toLineSet(String text) {
        Set<String> set = new HashSet<>();
        for (String line : text.split("\\n")) {
            String t = line.trim();
            if (!t.isEmpty()) set.add(t);
        }
        return set;
    }

    /** 优势 3: 大响应分段比较（避免头尾重叠） */
    private static double segmentedSim(String a, String b) {
        String aHead = a.substring(0, Math.min(HEAD_SIZE, a.length()));
        int aTailStart = Math.max(HEAD_SIZE, a.length() - TAIL_SIZE);
        String aTail = a.length() > HEAD_SIZE ? a.substring(aTailStart) : "";
        String bHead = b.substring(0, Math.min(HEAD_SIZE, b.length()));
        int bTailStart = Math.max(HEAD_SIZE, b.length() - TAIL_SIZE);
        String bTail = b.length() > HEAD_SIZE ? b.substring(bTailStart) : "";

        double headSim = jaccardLineSim(aHead, bHead);
        double tailSim = jaccardLineSim(aTail, bTail);
        return (headSim + tailSim) / 2.0;
    }

    /** Levenshtein 安全上限：任一字符串超过此值则回退到 Jaccard 行级相似度 */
    private static final int MAX_LEV = 2000;

    /** Levenshtein 距离 → 相似度 (优势 4: 快速失败) */
    private static double levenshteinImpl(String a, String b, double threshold) {
        if (a.equals(b)) return 1.0;

        int lenA = a.length(), lenB = b.length();
        int maxLen = Math.max(lenA, lenB);
        if (maxLen == 0) return 1.0;

        // 快速失败: 长度差过大
        if (Math.abs(lenA - lenB) > maxLen * (1 - threshold)) return 0.0;

        // 快速失败: 前 100 码点差异超大 (codePointAt 处理 Unicode 代理对)
        if (lenA > 100 && lenB > 100) {
            int prefixDist = 0, count = 0;
            int ia = 0, ib = 0;
            while (count < 100 && ia < lenA && ib < lenB) {
                int ca = a.codePointAt(ia), cb = b.codePointAt(ib);
                if (ca != cb) prefixDist++;
                ia += Character.charCount(ca);
                ib += Character.charCount(cb);
                count++;
            }
            if (prefixDist > 50) return 0.0;
        }

        // 任一字符串超过安全上限 → 回退到 Jaccard 行级相似度（避免 OOM）
        if (lenA > MAX_LEV || lenB > MAX_LEV) {
            return jaccardLineSim(a, b);
        }

        // 完整 Levenshtein 计算
        int[][] dp = new int[lenA + 1][lenB + 1];
        for (int i = 0; i <= lenA; i++) dp[i][0] = i;
        for (int j = 0; j <= lenB; j++) dp[0][j] = j;

        for (int i = 1; i <= lenA; i++) {
            for (int j = 1; j <= lenB; j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(
                        dp[i - 1][j] + 1,
                        dp[i][j - 1] + 1),
                        dp[i - 1][j - 1] + cost);
            }
        }
        return 1.0 - (double) dp[lenA][lenB] / maxLen;
    }

    /**
     * 优势 1: upgradeStr — 剥离公共前后缀
     * 输入 shorter.length() <= longer.length()
     * 返回 [shorter的差异部分, longer的差异部分]
     */
    public static String[] upgradeStr(String shorter, String longer) {
        int sLen = shorter.length(), lLen = longer.length();

        // 找公共前缀
        int prefix = 0;
        for (int i = 0; i < sLen; i++) {
            if (shorter.charAt(i) != longer.charAt(i)) break;
            prefix = i + 1;
        }

        // 找公共后缀（在去除前缀后的部分中查找）
        int sEnd = sLen, lEnd = lLen;
        int suffixLen = 0;
        while (suffixLen < sLen - prefix
                && shorter.charAt(sLen - 1 - suffixLen) == longer.charAt(lLen - 1 - suffixLen)) {
            suffixLen++;
        }
        sEnd = Math.max(prefix, sLen - suffixLen);
        lEnd = lLen - suffixLen;

        return new String[]{
                shorter.substring(prefix, sEnd),
                longer.substring(prefix, lEnd)
        };
    }
}
