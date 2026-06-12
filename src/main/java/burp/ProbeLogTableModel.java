package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ProbeLogTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "#", "时间", "方法", "URL", "参数", "Payload", "状态码", "长度", "耗时(ms)"
    };

    public static class Entry {
        public final int id;
        public final String time, method, url, param, payload;
        public final short statusCode;
        public final int responseLen;
        public final long elapsed;
        public final HttpRequestResponse requestResponse;

        Entry(int id, String time, String method, String url, String param, String payload,
              short code, int len, long elapsed, HttpRequestResponse rr) {
            this.id = id; this.time = time; this.method = method; this.url = url;
            this.param = param; this.payload = payload; this.statusCode = code;
            this.responseLen = len; this.elapsed = elapsed; this.requestResponse = rr;
        }
    }

    private final List<Entry> entries = new ArrayList<>();
    private int counter = 0;
    private static final int MAX_LOG_ENTRIES = 5000;

    @Override public synchronized int getRowCount() { return entries.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int c) { return COLUMNS[c]; }

    @Override
    public Class<?> getColumnClass(int c) {
        switch (c) {
            case 0: case 6: case 7: return Integer.class;
            case 8: return Long.class;
            default: return String.class;
        }
    }

    @Override
    public synchronized Object getValueAt(int row, int col) {
        if (row >= entries.size()) return "";
        Entry e = entries.get(row);
        switch (col) {
            case 0: return e.id;
            case 1: return e.time;
            case 2: return e.method;
            case 3: return e.url;
            case 4: return e.param;
            case 5: return e.payload != null && e.payload.length() > 80
                    ? e.payload.substring(0, 80) + "..." : e.payload;
            case 6: return (int) e.statusCode;
            case 7: return e.responseLen;
            case 8: return e.elapsed;
            default: return "";
        }
    }

    public synchronized void add(Entry e) {
        while (entries.size() >= MAX_LOG_ENTRIES) {
            entries.remove(0);
            fireTableRowsDeleted(0, 0);
        }
        int idx = entries.size(); entries.add(e); fireTableRowsInserted(idx, idx);
    }
    public synchronized Entry getEntry(int row) { return (row >= 0 && row < entries.size()) ? entries.get(row) : null; }
    public synchronized void clear() { entries.clear(); counter = 0; fireTableDataChanged(); }
    public synchronized int nextId() { return ++counter; }
}
