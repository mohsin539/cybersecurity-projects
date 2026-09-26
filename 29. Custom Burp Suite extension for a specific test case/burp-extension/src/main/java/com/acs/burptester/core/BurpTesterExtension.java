package com.acs.burptester.core;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.acs.burptester.modules.jwt.JwtTokenTestPack;

public final class BurpTesterExtension implements BurpExtension {

    private final TestCaseEngine engine = new TestCaseEngine().register(new JwtTokenTestPack());

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BurpTester - WSTG-SESS-10 (JWT)");
        api.logging().logToOutput("BurpTester initialized (engine v1, anchor hash verified at build).");
        api.logging().logToOutput("Available test cases: " + engine.availableIds());

        BurpHttpFacade http = new BurpHttpFacade(api.http());
        api.userInterface().registerSuiteTab("BurpTester", new BurpTesterSuiteTab(engine, http));
        api.userInterface().registerContextMenuItemsProvider(new TesterContextMenu(engine, http, api.logging()));

        LoopbackControlServer.start(engine, http);
        api.logging().logToOutput("Loopback control plane started; pairing file: "
                + LoopbackControlServer.pairingFile());
    }
}