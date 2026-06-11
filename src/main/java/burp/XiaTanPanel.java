package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.function.Consumer;

public class XiaTanPanel extends JPanel {

    private final MontoyaApi api;
    private final ScanEngine scanEngine;
    private final ScanTableModel tableModel;
    private final ProbeLogTableModel logModel;
    private JTable resultTable, logTable;
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private HttpRequestResponse currentItem;
    private xia_tan extender;
    private JLabel statusLabel;
    private JToggleButton btnFilter;

    // 统一视觉常量
    private static final Color BG_HEADER   = new Color(245, 245, 250);
    private static final Color BG_ALT_ROW  = new Color(250, 250, 255);
    private static final Color BG_WHITE    = Color.WHITE;
    private static final Color C_HIGH      = new Color(255, 210, 210);
    private static final Color C_MED       = new Color(255, 240, 200);
    private static final Font  FONT_TITLE  = new Font(Font.SANS_SERIF, Font.BOLD, 12);
    private static final Font  FONT_NORMAL = new Font(Font.SANS_SERIF, Font.PLAIN, 11);

    public XiaTanPanel(MontoyaApi api, ScanEngine scanEngine, xia_tan extender) {
        this.api = api;
        this.scanEngine = scanEngine;
        this.extender = extender;
        this.tableModel = new ScanTableModel();
        scanEngine.setTableModel(tableModel);
        this.logModel = new ProbeLogTableModel();
        scanEngine.setLogModel(logModel);

        setLayout(new BorderLayout());
        setFont(FONT_NORMAL);

        add(buildConfigPanel(), BorderLayout.NORTH);
        add(buildMainContent(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
    }

    // ==================== Status Bar ====================

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(new CompoundBorder(
                new MatteBorder(1, 0, 0, 0, new Color(200, 200, 210)),
                new EmptyBorder(2, 10, 2, 10)));
        bar.setBackground(new Color(245, 245, 248));

        statusLabel = new JLabel("● 就绪");
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        bar.add(statusLabel, BorderLayout.WEST);

        JLabel hint = new JLabel("点击行查看请求/响应 | 右键复制");
        hint.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        hint.setForeground(Color.GRAY);
        bar.add(hint, BorderLayout.EAST);

        // 定时刷新状态
        new javax.swing.Timer(2000, e -> updateStatus()).start();
        return bar;
    }

    private void updateStatus() {
        int results = tableModel.getRowCount();
        int logs = logModel.getRowCount();
        String s = "● 就绪";
        if (results > 0) s = "🔴 发现 " + results + " 个漏洞";
        if (logs > 0) s += "  |  探测 " + logs + " 次";
        statusLabel.setText(s);
    }

    // ==================== Main Content ====================

    private JPanel buildMainContent() {
        // -- Results table --
        resultTable = createTable(tableModel, new int[]{32, 105, 36, 175, 68, 48, 52, 138, 38});
        resultTable.setAutoCreateRowSorter(true);
        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = resultTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = resultTable.convertRowIndexToModel(viewRow);
                ScanResult r = tableModel.getResult(modelRow);
                if (r != null && r.requestResponse != null) {
                    currentItem = r.requestResponse;
                    showInViewers(r.requestResponse);
                }
            }
        });
        JScrollPane resultScroll = wrapScroll(resultTable, "检测结果");

        JPopupMenu pop = new JPopupMenu();
        JMenuItem cpUrl = new JMenuItem("复制 URL");
        cpUrl.addActionListener(e -> copySelected(r -> r.path));
        pop.add(cpUrl);
        JMenuItem cpEv = new JMenuItem("复制证据");
        cpEv.addActionListener(e -> copySelected(r -> r.evidence));
        pop.add(cpEv);
        resultTable.setComponentPopupMenu(pop);

        // -- Logs table --
        logTable = createTable(logModel, new int[]{28, 46, 36, 175, 62, 155, 36, 46, 52});
        logTable.setAutoCreateRowSorter(true);
        logTable.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = logTable.getSelectedRow();
            if (viewRow >= 0) {
                int modelRow = logTable.convertRowIndexToModel(viewRow);
                ProbeLogTableModel.Entry entry = logModel.getEntry(modelRow);
                if (entry != null && entry.requestResponse != null
                        && entry.requestResponse.request() != null) {
                    currentItem = entry.requestResponse;
                    showInViewers(entry.requestResponse);
                }
            }
        });
        JScrollPane logScroll = wrapScroll(logTable, "探测日志");

        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, resultScroll, logScroll);
        leftSplit.setResizeWeight(0.55);
        leftSplit.setDividerSize(5);
        leftSplit.setBorder(null);
        resultScroll.setMinimumSize(new Dimension(400, 100));
        logScroll.setMinimumSize(new Dimension(400, 60));

        // -- Request/Response viewers --
        requestViewer = api.userInterface().createHttpRequestEditor();
        responseViewer = api.userInterface().createHttpResponseEditor();

        JPanel reqPanel = wrapViewer(requestViewer.uiComponent(), "请求");
        JPanel respPanel = wrapViewer(responseViewer.uiComponent(), "响应");

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, reqPanel, respPanel);
        rightSplit.setResizeWeight(0.45);
        rightSplit.setDividerSize(5);
        rightSplit.setBorder(null);
        reqPanel.setMinimumSize(new Dimension(250, 80));
        respPanel.setMinimumSize(new Dimension(250, 80));

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, rightSplit);
        mainSplit.setResizeWeight(0.60);
        mainSplit.setDividerSize(5);
        mainSplit.setBorder(null);

        JPanel center = new JPanel(new BorderLayout());
        center.add(mainSplit, BorderLayout.CENTER);
        return center;
    }

    // ==================== Config Panel ====================

    private DefaultListModel<String> domainWLModel, domainBLModel, pathBLModel, pathWLModel;
    private JPanel filterPanel;

    private JPanel buildConfigPanel() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBorder(new CompoundBorder(
                new MatteBorder(0, 0, 1, 0, new Color(200, 200, 210)),
                new EmptyBorder(5, 8, 5, 8)));
        outer.setBackground(BG_HEADER);

        JPanel grid = new JPanel(new GridBagLayout());
        grid.setBackground(BG_HEADER);
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.HORIZONTAL;
        g.insets = new Insets(2, 4, 2, 4);
        g.weightx = 1;

        // Row 0: Module switches
        JPanel row0 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row0.setBackground(BG_HEADER);
        row0.add(buildSwitchGroup("检测模块",
                cb("XSS",true, v->scanEngine.enableXSS=v),
                cb("SQLi",true, v->scanEngine.enableSQLi=v),
                cb("SSTI",true, v->scanEngine.enableSSTI=v),
                cb("NoSQLi",true,v->scanEngine.enableNoSQLi=v),
                cb("延时",true, v->scanEngine.enableTimeSQLi=v),
                cb("Cookie",false,v->scanEngine.enableCookie=v)));
        row0.add(sep());
        row0.add(buildSwitchGroup("监控",
                cb("代理",false,v->{if(extender!=null)extender.monitorProxy=v;}),
                cb("重放",false,v->{if(extender!=null)extender.monitorRepeater=v;})));
        row0.add(sep());
        row0.add(buildSwitchGroup("CUD",
                cb("增",false,v->scanEngine.scanAdd=v),
                cb("删",false,v->scanEngine.scanDel=v),
                cb("改",false,v->scanEngine.scanMod=v)));
        g.gridy = 0; grid.add(row0, g);

        // Row 1: Thresholds
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row1.setBackground(BG_HEADER);
        row1.add(lbl("排除参数:"));
        JTextField tEx = tf("csrf,token,_t,timestamp", 14);
        sync(tEx, v->scanEngine.excludeParams=v);
        row1.add(tEx);
        row1.add(sep());
        row1.add(lbl("请求间隔:"));
        JTextField tDl = tf("0", 3);
        syncNum(tDl,"0", v->scanEngine.delayMs=Integer.parseInt(v.trim()));
        row1.add(tDl);
        row1.add(lbl("ms"));
        row1.add(lbl(" 延时阈值:"));
        JTextField tTt = tf("5000", 4);
        syncNum(tTt,"5000", v->scanEngine.timeThreshold=Long.parseLong(v.trim()));
        row1.add(tTt);
        row1.add(lbl("ms"));
        row1.add(lbl(" 相似度:"));
        JTextField tSm = tf("0.9", 3);
        syncNum(tSm,"0.9", v->scanEngine.simThreshold=Double.parseDouble(v.trim()));
        row1.add(tSm);

        btnFilter = new JToggleButton("▸ 黑白名单");
        btnFilter.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        btnFilter.addActionListener(e -> {
            filterPanel.setVisible(btnFilter.isSelected());
            updateFilterButtonText();
        });
        row1.add(btnFilter);

        JButton btnClear = new JButton("清除全部");
        btnClear.setFont(FONT_NORMAL);
        btnClear.addActionListener(e->{
            tableModel.clear(); logModel.clear(); scanEngine.clearDedup();
            requestViewer.setRequest(null); responseViewer.setResponse(null);
            updateStatus();
        });
        row1.add(btnClear);

        JButton btnStop = new JButton("停止扫描");
        btnStop.setFont(FONT_NORMAL);
        btnStop.setForeground(Color.RED);
        btnStop.addActionListener(e -> { scanEngine.cancelAllScans(); updateStatus(); });
        row1.add(btnStop);
        g.gridy = 1; grid.add(row1, g);

        // Row 2: Filter lists (hidden)
        filterPanel = buildFilterLists();
        loadFilterListsFromEngine();  // 从 ScanEngine 同步初始默认值到 UI
        filterPanel.setVisible(false);
        updateFilterButtonText();
        filterPanel.setBackground(BG_HEADER);
        g.gridy = 2; grid.add(filterPanel, g);

        outer.add(grid, BorderLayout.CENTER);
        return outer;
    }

    // ==================== Filter Lists ====================

    private JPanel buildFilterLists() {
        domainWLModel = new DefaultListModel<>();
        domainBLModel = new DefaultListModel<>();
        pathBLModel   = new DefaultListModel<>();
        pathWLModel   = new DefaultListModel<>();

        JPanel panel = new JPanel(new GridLayout(2, 2, 10, 8));
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 200)),
                "黑白名单过滤器 (一行一条，支持通配符 * )",
                TitledBorder.LEFT, TitledBorder.TOP, FONT_TITLE));

        panel.add(listGroup("✅ 域名白名单 — 仅扫描这些", domainWLModel,
                v -> scanEngine.domainWhitelist = v));
        panel.add(listGroup("🔒 域名黑名单 — 不扫描这些", domainBLModel,
                v -> scanEngine.domainBlacklist = v));
        panel.add(listGroup("✅ 路径白名单 — 仅扫描这些", pathWLModel,
                v -> scanEngine.pathWhitelist = v));
        panel.add(listGroup("🔒 路径黑名单 — 不扫描这些", pathBLModel,
                v -> scanEngine.pathBlacklist = v));

        return panel;
    }

    private JPanel listGroup(String title, DefaultListModel<String> model,
                              Consumer<String> syncToEngine) {
        JPanel p = new JPanel(new BorderLayout(3, 3));
        p.setBorder(new EmptyBorder(4, 4, 4, 4));

        // Top row: title + remove
        JPanel top = new JPanel(new BorderLayout());
        top.add(new JLabel(title), BorderLayout.WEST);
        JButton btnRem = new JButton("− 删除");
        btnRem.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        top.add(btnRem, BorderLayout.EAST);
        p.add(top, BorderLayout.NORTH);

        // List
        JList<String> list = new JList<>(model);
        list.setFont(FONT_NORMAL);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setVisibleRowCount(4);
        JScrollPane scroll = new JScrollPane(list);
        scroll.setPreferredSize(new Dimension(180, 70));
        p.add(scroll, BorderLayout.CENTER);

        btnRem.addActionListener(e -> {
            int idx = list.getSelectedIndex();
            if (idx >= 0) { model.remove(idx); syncModel(model, syncToEngine); }
        });

        // Input row
        JPanel inputRow = new JPanel(new BorderLayout(3, 0));
        JTextField input = new JTextField();
        input.setFont(FONT_NORMAL);
        input.addActionListener(e -> addItem(input, model, syncToEngine));
        JButton btnAdd = new JButton("＋");
        btnAdd.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        btnAdd.setMargin(new Insets(0, 8, 0, 8));
        btnAdd.addActionListener(e -> addItem(input, model, syncToEngine));
        inputRow.add(input, BorderLayout.CENTER);
        inputRow.add(btnAdd, BorderLayout.EAST);
        p.add(inputRow, BorderLayout.SOUTH);

        return p;
    }

    // ==================== Helpers ====================

    private JCheckBox cb(String text, boolean def, java.util.function.Consumer<Boolean> setter) {
        JCheckBox c = new JCheckBox(text, def);
        c.setFont(FONT_NORMAL);
        c.setBackground(BG_HEADER);
        c.addActionListener(e -> setter.accept(c.isSelected()));
        return c;
    }

    private JLabel lbl(String text) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_NORMAL);
        return l;
    }

    private JTextField tf(String text, int cols) {
        JTextField f = new JTextField(text, cols);
        f.setFont(FONT_NORMAL);
        return f;
    }

    private JSeparator sep() {
        JSeparator s = new JSeparator(JSeparator.VERTICAL);
        s.setPreferredSize(new Dimension(1, 18));
        return s;
    }

    private JPanel buildSwitchGroup(String title, JCheckBox... boxes) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 2, 0));
        p.setBackground(BG_HEADER);
        JLabel l = new JLabel(title);
        l.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        l.setForeground(new Color(100, 100, 130));
        p.add(l);
        for (JCheckBox b : boxes) p.add(b);
        return p;
    }

    private JTable createTable(AbstractTableModel model, int[] widths) {
        JTable t = new JTable(model);
        t.setFont(FONT_NORMAL);
        t.setRowHeight(20);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setShowGrid(false);
        t.setIntercellSpacing(new Dimension(0, 0));
        t.setDefaultRenderer(Object.class, new CellRenderer());
        t.getTableHeader().setFont(FONT_TITLE);
        t.getTableHeader().setBackground(BG_HEADER);
        t.getTableHeader().setBorder(new MatteBorder(0, 0, 2, 0, new Color(180, 180, 200)));
        for (int i = 0; i < widths.length && i < t.getColumnCount(); i++)
            t.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        return t;
    }

    private JScrollPane wrapScroll(JTable table, String title) {
        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 215)),
                title, TitledBorder.LEFT, TitledBorder.TOP, FONT_TITLE));
        sp.getViewport().setBackground(BG_WHITE);
        return sp;
    }

    private JPanel wrapViewer(Component viewer, String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 215)),
                title, TitledBorder.LEFT, TitledBorder.TOP, FONT_TITLE));
        p.add(viewer, BorderLayout.CENTER);
        return p;
    }

    private void showInViewers(HttpRequestResponse rr) {
        if (rr.request() != null) requestViewer.setRequest(rr.request());
        if (rr.response() != null) responseViewer.setResponse(rr.response());
    }

    private void addItem(JTextField input, DefaultListModel<String> model, Consumer<String> sync) {
        String item = input.getText().trim();
        if (!item.isEmpty() && !model.contains(item)) {
            model.addElement(item);
            syncModel(model, sync);
        }
        input.setText("");
    }

    private void syncModel(DefaultListModel<String> model, Consumer<String> sync) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < model.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(model.get(i));
        }
        sync.accept(sb.toString());
        updateFilterButtonText();
    }

    private void updateFilterButtonText() {
        int total = domainWLModel.size() + domainBLModel.size() + pathWLModel.size() + pathBLModel.size();
        btnFilter.setText((btnFilter.isSelected() ? "▾" : "▸") + " 黑白名单 (" + total + ")");
    }

    /** 从 ScanEngine 的逗号分隔字符串加载初始默认值到 UI 列表 */
    private void loadFilterListsFromEngine() {
        loadModel(domainWLModel, scanEngine.domainWhitelist);
        loadModel(domainBLModel, scanEngine.domainBlacklist);
        loadModel(pathWLModel, scanEngine.pathWhitelist);
        loadModel(pathBLModel, scanEngine.pathBlacklist);
    }

    private void loadModel(DefaultListModel<String> model, String csv) {
        if (csv == null || csv.trim().isEmpty()) return;
        for (String item : csv.split(",")) {
            String v = item.trim();
            if (!v.isEmpty()) model.addElement(v);
        }
    }

    private void copySelected(java.util.function.Function<ScanResult, String> fn) {
        int r = resultTable.getSelectedRow();
        if (r >= 0) {
            ScanResult s = tableModel.getResult(r);
            if (s != null) Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(fn.apply(s)), null);
        }
    }

    // ==================== Sync Helpers ====================

    private static void sync(JTextField f, Consumer<String> set) {
        set.accept(f.getText());
        f.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { set.accept(f.getText()); }
            @Override public void removeUpdate(DocumentEvent e) { set.accept(f.getText()); }
            @Override public void changedUpdate(DocumentEvent e) { set.accept(f.getText()); }
        });
    }

    private static void syncNum(JTextField f, String fb, Consumer<String> set) {
        set.accept(f.getText());
        f.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e)  { tryParse(); }
            @Override public void removeUpdate(DocumentEvent e)  { tryParse(); }
            @Override public void changedUpdate(DocumentEvent e) { tryParse(); }
            void tryParse() {
                try { set.accept(f.getText()); f.setBackground(Color.WHITE); }
                catch (NumberFormatException x) { f.setBackground(new Color(255, 220, 220)); }
            }
        });
    }

    // ==================== Cell Renderer ====================

    private static class CellRenderer extends DefaultTableCellRenderer {
        private static final Color SEL_BG = new Color(51, 153, 255);

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean foc, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, v, sel, foc, row, col);

            if (sel) {
                c.setBackground(SEL_BG);
                c.setForeground(Color.WHITE);
            } else {
                // 严重性着色
                try {
                    String sev = t.getValueAt(row, 6).toString();
                    if ("High".equals(sev)) c.setBackground(C_HIGH);
                    else if ("Medium".equals(sev)) c.setBackground(C_MED);
                    else c.setBackground(row % 2 == 0 ? BG_WHITE : BG_ALT_ROW);
                } catch (Exception ignored) {
                    c.setBackground(row % 2 == 0 ? BG_WHITE : BG_ALT_ROW);
                }
                c.setForeground(Color.BLACK);
            }

            // 列对齐
            if (c instanceof JLabel) {
                JLabel l = (JLabel) c;
                if (col == 0 || col == 2 || col == 8) l.setHorizontalAlignment(SwingConstants.CENTER);
                else l.setHorizontalAlignment(SwingConstants.LEFT);
                if (col == 0) l.setFont(l.getFont().deriveFont(Font.PLAIN, 10f));
            }
            setBorder(new EmptyBorder(1, 4, 1, 4));
            return c;
        }
    }
}
