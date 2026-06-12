package burp.util;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Arrays;
import java.util.Collections;

public class StructuralSignatureTest {

    @Test
    public void signature_restPathWithInt_normalizesToPlaceholder() {
        String sig = StructuralSignature.signature("GET", "/user/123/profile",
                Collections.singletonList("id"));
        assertTrue(sig.contains("{int}"));
    }

    @Test
    public void signature_uuidPath_normalizesToPlaceholder() {
        String sig = StructuralSignature.signature("GET",
                "/api/550e8400-e29b-41d4-a716-446655440000",
                Collections.emptyList());
        assertTrue(sig.contains("{uuid}"));
    }

    @Test
    public void signature_hexPath_normalizesToPlaceholder() {
        String sig = StructuralSignature.signature("GET", "/session/a1b2c3d4e5f6",
                Collections.emptyList());
        assertTrue(sig.contains("{hex}"));
    }

    @Test
    public void signature_stripsQueryString() {
        String sig1 = StructuralSignature.signature("GET", "/api/users?id=1",
                Collections.singletonList("id"));
        String sig2 = StructuralSignature.signature("GET", "/api/users?id=999",
                Collections.singletonList("id"));
        assertEquals(sig1, sig2);
    }

    @Test
    public void signature_filtersNoiseParams() {
        String sig1 = StructuralSignature.signature("GET", "/api/data",
                Arrays.asList("id", "timestamp", "_t"));
        String sig2 = StructuralSignature.signature("GET", "/api/data",
                Arrays.asList("id", "_ts"));
        // timestamp 和 _t 是噪声参数，被过滤，所以签名相同
        assertTrue(sig1.contains("id"));
        assertFalse(sig1.contains("timestamp"));
        assertFalse(sig1.contains("_t"));
    }
}
