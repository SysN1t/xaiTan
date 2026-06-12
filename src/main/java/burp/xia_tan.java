package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class xia_tan implements BurpExtension, HttpHandler, ContextMenuItemsProvider {

    private MontoyaApi api;
    private XiaTanPanel panel;
    private ScanEngine scanEngine;
    volatile boolean monitorProxy = false;
    volatile boolean monitorRepeater = false;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("xia_tan v2.1 (Montoya)");

        scanEngine = new ScanEngine(api);

        SwingUtilities.invokeLater(() -> {
            panel = new XiaTanPanel(api, scanEngine, this);
            api.userInterface().registerSuiteTab("xia_tan", panel);
        });

        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);

        api.logging().logToOutput("==============================================");
        api.logging().logToOutput("  xia_tan v2.1 loaded! (Montoya API)");
        api.logging().logToOutput("  Author: SysN3t");
        api.logging().logToOutput("  Probe: XSS / SQLi / SSTI / NoSQLi");
        api.logging().logToOutput("  Right-click -> Send to xia_tan");
        api.logging().logToOutput("==============================================");
    }

    // ==================== HttpHandler ====================

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        return RequestToBeSentAction.continueWith(req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        if (monitorProxy && resp.toolSource().isFromTool(burp.api.montoya.core.ToolType.PROXY)) {
            scanEngine.scanAsync(HttpRequestResponse.httpRequestResponse(
                    resp.initiatingRequest(), resp));
        }
        if (monitorRepeater && resp.toolSource().isFromTool(burp.api.montoya.core.ToolType.REPEATER)) {
            scanEngine.scanAsync(HttpRequestResponse.httpRequestResponse(
                    resp.initiatingRequest(), resp));
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    // ==================== ContextMenu ====================

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        if (event.selectedRequestResponses().isEmpty()) return items;

        JMenuItem scanAll = new JMenuItem("发送到 xia_tan");
        scanAll.addActionListener(e -> {
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                scanEngine.scanAsync(rr);
            }
        });
        items.add(scanAll);

        JMenu sub = new JMenu("xia_tan 选择性扫描...");
        sub.add(item("仅 XSS",   event, true, false, false, false));
        sub.add(item("仅 SQLi",  event, false,true, false, false));
        sub.add(item("仅 SSTI",  event, false,false,true, false));
        sub.add(item("仅 NoSQLi",event, false,false,false,true));
        items.add(sub);

        return items;
    }

    private JMenuItem item(String label, ContextMenuEvent event,
                           boolean xss, boolean sqli, boolean ssti, boolean nosqli) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(e -> {
            ScanEngine.ScanConfig cfg = scanEngine.buildSelectiveConfig(xss, sqli, ssti, nosqli);
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                scanEngine.scanAsync(rr, cfg);
            }
        });
        return mi;
    }
}
