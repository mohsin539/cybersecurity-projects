package com.acs.burptester.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.HttpFacade;
import com.acs.burptester.api.TestProfile;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.List;
import java.util.Map;

public final class TesterContextMenu implements ContextMenuItemsProvider {

    private final TestCaseEngine engine;
    private final HttpFacade http;
    private final Logging logging;

    public TesterContextMenu(TestCaseEngine engine, HttpFacade http, Logging logging) {
        this.engine = engine;
        this.http = http;
        this.logging = logging;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        return event.messageEditorRequestResponse()
                .map(mrr -> {
                    HttpRequestResponse requestResponse = mrr.requestResponse();
                    HttpRequest request = requestResponse.request();
                    FacadeRequest target = Requests.toFacadeRequest(request);
                    JMenuItem item = new JMenuItem("BurpTester > Run WSTG-SESS-10 (JWT)");
                    item.addActionListener(e -> run(target));
                    return List.<Component>of(item);
                })
                .orElseGet(List::of);
    }

    private void run(FacadeRequest target) {
        TestProfile profile = new TestProfile("context-menu", "Context menu run",
                true, 20, 250L, List.of("WSTG-SESS-10"), List.of());
        Runner.run(engine, "WSTG-SESS-10", profile, target, http,
                progress -> logging.logToOutput(progress), null);
    }
}