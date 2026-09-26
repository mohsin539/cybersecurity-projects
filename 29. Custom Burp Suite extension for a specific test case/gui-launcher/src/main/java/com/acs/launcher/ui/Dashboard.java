package com.acs.launcher.ui;

import com.acs.burptester.core.TestCaseEngine;
import com.acs.burptester.modules.jwt.JwtTokenTestPack;
import com.acs.launcher.core.SessionState;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Stage;

public final class Dashboard {

    private final TestCaseEngine engine = new TestCaseEngine().register(new JwtTokenTestPack());
    private final SessionState session = new SessionState();
    private final DashboardPanel runPanel;
    private final ConfigEditorPanel configPanel;
    private final ReportPanel reportPanel;

    public Dashboard() {
        reportPanel = new ReportPanel(session);
        runPanel = new DashboardPanel(engine, session, this::refreshViews);
        configPanel = new ConfigEditorPanel(engine, runPanel::applyProfile);
    }

    public void show(Stage stage) {
        runPanel.setOwnerStage(stage);
        configPanel.setOwnerStage(stage);
        reportPanel.setOwnerStage(stage);

        TabPane tabs = new TabPane();
        tabs.getTabs().addAll(
                tab("Dashboard", runPanel.node()),
                tab("Config Editor", configPanel.node()),
                tab("Reports", reportPanel.node()));

        BorderPane root = new BorderPane();
        root.setCenter(tabs);

        stage.setTitle("BurpTester - GUI portable launcher (WSTG-SESS-10 test-case engine)");
        stage.setScene(new Scene(root, 1240, 780));
        stage.show();
    }

    private static Tab tab(String name, Node content) {
        Tab tab = new Tab(name, content);
        tab.setClosable(false);
        return tab;
    }

    private void refreshViews() {
        Platform.runLater(() -> {
            runPanel.updateCounters();
            reportPanel.refreshSummary();
        });
    }
}