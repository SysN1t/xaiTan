package burp;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ScanTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
        "#", "主机", "方法", "URL", "参数", "类型", "严重性", "详情", "状态码"
    };

    private final List<ScanResult> results = new ArrayList<>();

    @Override public synchronized int getRowCount() { return results.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int c) { return COLUMNS[c]; }

    @Override
    public Class<?> getColumnClass(int c) {
        return c == 0 || c == 8 ? Integer.class : String.class;
    }

    @Override
    public synchronized Object getValueAt(int row, int col) {
        if (row >= results.size()) return "";
        ScanResult r = results.get(row);
        switch (col) {
            case 0: return r.id;
            case 1: return r.host;
            case 2: return r.method;
            case 3: return r.path;
            case 4: return r.paramName;
            case 5: return r.type;
            case 6: return r.severity;
            case 7: return r.detail;
            case 8: return r.requestResponse != null && r.requestResponse.response() != null
                    ? r.requestResponse.response().statusCode() : 0;
            default: return "";
        }
    }

    public synchronized void addResult(ScanResult r) {
        int idx = results.size();
        results.add(r);
        fireTableRowsInserted(idx, idx);
    }

    public synchronized ScanResult getResult(int row) {
        return (row >= 0 && row < results.size()) ? results.get(row) : null;
    }

    public synchronized void clear() {
        if (!results.isEmpty()) { results.clear(); fireTableDataChanged(); }
    }
}
