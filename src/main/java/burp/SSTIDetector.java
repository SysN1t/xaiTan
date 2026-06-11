package burp;

public class SSTIDetector {

    public static final int[][] OPERANDS = {
        {91371, 91373}, {91374, 91376}, {91377, 91379},
        {91380, 91382}, {91383, 91385}, {91386, 91388}
    };
    public static final long[] EXPECTED_RESULTS = new long[OPERANDS.length];
    public static final String[] EXPECTED_STRINGS = new String[OPERANDS.length];
    public static final String[] FAMILY_NAMES = {
        "Jinja2/Twig/Pebble/Nunjucks", "Freemarker/Mako/Groovy/EL/Velocity",
        "ERB/EJS/ASP", "SpEL/Jade/Pug", "Razor (.NET)", "Smarty (PHP)"
    };

    static {
        for (int i = 0; i < OPERANDS.length; i++) {
            EXPECTED_RESULTS[i] = (long) OPERANDS[i][0] * OPERANDS[i][1];
            EXPECTED_STRINGS[i] = String.valueOf(EXPECTED_RESULTS[i]);
        }
    }

    public static String getCombinedPayload() {
        StringBuilder sb = new StringBuilder();
        sb.append("{{").append(OPERANDS[0][0]).append("*").append(OPERANDS[0][1]).append("}}");
        sb.append("${").append(OPERANDS[1][0]).append("*").append(OPERANDS[1][1]).append("}");
        sb.append("<%=").append(OPERANDS[2][0]).append("*").append(OPERANDS[2][1]).append("%>");
        sb.append("#{").append(OPERANDS[3][0]).append("*").append(OPERANDS[3][1]).append("}");
        sb.append("@(").append(OPERANDS[4][0]).append("*").append(OPERANDS[4][1]).append(")");
        sb.append("{").append(OPERANDS[5][0]).append("*").append(OPERANDS[5][1]).append("}");
        return sb.toString();
    }
}
