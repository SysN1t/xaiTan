package burp.util;

import org.junit.Test;
import static org.junit.Assert.*;

public class MyCompareTest {

    @Test
    public void similarity_sameString_returnsOne() {
        assertEquals(1.0, MyCompare.similarity("abc", "abc"), 0.001);
    }

    @Test
    public void similarity_emptyBoth_returnsOne() {
        assertEquals(1.0, MyCompare.similarity("", ""), 0.001);
    }

    @Test
    public void similarity_nullBoth_returnsOne() {
        assertEquals(1.0, MyCompare.similarity(null, null), 0.001);
    }

    @Test
    public void similarity_nullAndNonNull_returnsZero() {
        assertEquals(0.0, MyCompare.similarity(null, "abc"), 0.001);
    }

    @Test
    public void similarity_veryDifferent_returnsLow() {
        double sim = MyCompare.similarity("hello world foo bar", "xyz abc def ghi");
        assertTrue("Expected low similarity, got " + sim, sim < 0.5);
    }

    @Test
    public void levenshtein_sameString_returnsOne() {
        assertEquals(1.0, MyCompare.levenshtein("test", "test"), 0.001);
    }

    @Test
    public void levenshtein_oneCharDiff() {
        double sim = MyCompare.levenshtein("abc", "abd");
        assertTrue("Expected high similarity, got " + sim, sim > 0.6);
    }

    @Test
    public void levenshtein_largeInput_fallsBackToJaccard() {
        // 构造 3000 字符的字符串（超过 MAX_LEV=2000），应走 Jaccard 回退，不 OOM
        StringBuilder sb1 = new StringBuilder();
        StringBuilder sb2 = new StringBuilder();
        for (int i = 0; i < 300; i++) {
            sb1.append("line").append(i).append(": hello world foo bar baz\n");
            sb2.append("line").append(i).append(": hello world foo bar baz\n");
        }
        sb2.append("extra different content at the end\n");
        double sim = MyCompare.levenshtein(sb1.toString(), sb2.toString());
        assertTrue("Large input should produce valid similarity", sim >= 0.0 && sim <= 1.0);
    }

    @Test
    public void fmt_formatsPercentage() {
        assertTrue(MyCompare.fmt(0.95).contains("%"));
    }
}
