package burp;

public class ResponseComparer {

    // ==================== Domain Matching ====================

    public static boolean isDomainAllowed(String host, String whitelist) {
        if (whitelist == null || whitelist.trim().isEmpty()) return true;
        host = cleanHost(host);
        for (String raw : whitelist.split(",")) {
            String p = cleanHost(raw.trim());
            if (p.isEmpty()) continue;
            if (matchDomain(host, p)) return true;
        }
        return false;
    }

    public static boolean isDomainBlocked(String host, String blacklist) {
        if (blacklist == null || blacklist.trim().isEmpty()) return false;
        host = cleanHost(host);
        for (String raw : blacklist.split(",")) {
            String p = cleanHost(raw.trim());
            if (p.isEmpty()) continue;
            if (matchDomain(host, p)) return true;
        }
        return false;
    }

    /**
     * Strip scheme, port, and trailing slash from a host/URL string.
     * e.g. "https://example.com:8080/" → "example.com"
     */
    static String cleanHost(String s) {
        if (s == null) return "";
        s = s.trim().toLowerCase();
        if (s.startsWith("http://"))  s = s.substring(7);
        if (s.startsWith("https://")) s = s.substring(8);
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(0, colon);
        return s.trim();
    }

    private static boolean matchDomain(String host, String pattern) {
        if ("*".equals(pattern)) return true;
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1);
            return host.endsWith(suffix) || host.equals(pattern.substring(2));
        }
        return host.equals(pattern);
    }

    // ==================== Path Matching ====================

    public static boolean isPathBlocked(String path, String blacklist) {
        if (blacklist == null || blacklist.trim().isEmpty()) return false;
        for (String raw : blacklist.split(",")) {
            String p = raw.trim();
            if (p.isEmpty()) continue;
            if (matchPath(path, p)) return true;
        }
        return false;
    }

    public static boolean isPathAllowed(String path, String whitelist) {
        if (whitelist == null || whitelist.trim().isEmpty()) return true;
        for (String raw : whitelist.split(",")) {
            String p = raw.trim();
            if (p.isEmpty()) continue;
            if (matchPath(path, p)) return true;
        }
        return false;
    }

    private static boolean matchPath(String path, String pattern) {
        // 剥离 query string，避免 /style.css?v=1 无法匹配 *.css
        int qm = path.indexOf('?');
        if (qm >= 0) path = path.substring(0, qm);
        // 规范化：去掉尾斜杠，避免 /api/ ≠ /api 的误判
        if (path.endsWith("/")) path = path.substring(0, path.length() - 1);
        if (pattern.endsWith("/")) pattern = pattern.substring(0, pattern.length() - 1);
        if ("*".equals(pattern)) return true;
        boolean startsW = pattern.startsWith("*");
        boolean endsW = pattern.endsWith("*");
        if (startsW && endsW && pattern.length() > 2) {
            return path.contains(pattern.substring(1, pattern.length() - 1));
        }
        if (endsW) {
            return path.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        if (startsW) {
            return path.endsWith(pattern.substring(1));
        }
        return path.equals(pattern);
    }
}
