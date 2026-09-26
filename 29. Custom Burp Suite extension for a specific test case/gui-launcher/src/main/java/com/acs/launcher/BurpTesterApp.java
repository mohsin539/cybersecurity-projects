package com.acs.launcher;

import com.acs.launcher.ui.Dashboard;
import javafx.application.Application;
import javafx.stage.Stage;

public final class BurpTesterApp extends Application {

    @Override
    public void start(Stage stage) {
        new Dashboard().show(stage);
    }
}