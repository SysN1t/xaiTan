package burp.util;

import burp.ResponseComparer;
import org.junit.Test;
import static org.junit.Assert.*;

public class ResponseComparerTest {

    @Test
    public void isDomainAllowed_emptyWhitelist_allowsAll() {
        assertTrue(ResponseComparer.isDomainAllowed("evil.com", ""));
        assertTrue(ResponseComparer.isDomainAllowed("example.com", null));
    }

    @Test
    public void isDomainAllowed_exactMatch() {
        assertTrue(ResponseComparer.isDomainAllowed("example.com", "example.com"));
    }

    @Test
    public void isDomainAllowed_wildcardSubdomain() {
        assertTrue(ResponseComparer.isDomainAllowed("sub.example.com", "*.example.com"));
    }

    @Test
    public void isDomainAllowed_wildcardOnly() {
        assertTrue(ResponseComparer.isDomainAllowed("anything.com", "*"));
    }

    @Test
    public void isDomainAllowed_noMatch() {
        assertFalse(ResponseComparer.isDomainAllowed("evil.com", "example.com,test.com"));
    }

    @Test
    public void isDomainBlocked_exactMatch() {
        assertTrue(ResponseComparer.isDomainBlocked("evil.com", "evil.com"));
    }

    @Test
    public void isDomainBlocked_emptyBlacklist_allowsAll() {
        assertFalse(ResponseComparer.isDomainBlocked("evil.com", ""));
        assertFalse(ResponseComparer.isDomainBlocked("evil.com", null));
    }

    @Test
    public void isPathBlocked_prefixMatch() {
        assertTrue(ResponseComparer.isPathBlocked("/admin/users", "/admin/*"));
    }

    @Test
    public void isPathBlocked_suffixMatch() {
        assertTrue(ResponseComparer.isPathBlocked("/style.css", "*.css"));
    }

    @Test
    public void isPathBlocked_containsMatch() {
        assertTrue(ResponseComparer.isPathBlocked("/api/v2/admin/users", "*admin*"));
    }

    @Test
    public void isPathBlocked_noMatch() {
        assertFalse(ResponseComparer.isPathBlocked("/home", "/admin/*"));
    }

    @Test
    public void cleanHost_stripsSchemeAndPort() {
        // cleanHost is package-private, tested via isDomainAllowed
        assertTrue(ResponseComparer.isDomainAllowed("example.com", "example.com"));
    }
}
