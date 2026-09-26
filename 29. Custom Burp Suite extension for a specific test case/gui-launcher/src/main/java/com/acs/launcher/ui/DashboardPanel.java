package com.acs.launcher.ui;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;
import com.acs.burptester.api.TestProfile;
import com.acs.burptester.core.DirectHttpFacade;
import com.acs.burptester.core.LoopbackControlServer;
import com.acs.burptester.core.Profiles;
import com.acs.burptester.core.Requests;
import com.acs.burptester.core.Runner;
import com.acs.burptester.core.TestCaseEngine;
import com.acs.launcher.FindingRow;
import com.acs.launcher.core.PairingClient;
import com.acs.launcher.core.SessionState;
import com.acs.launcher.report.ReportBuilder;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Files;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class DashboardPanel {

    private final TestCaseEngine engine;
    private final SessionState session;
    private final Runnable onDataChanged;
    private final ObservableList<FindingRow> rows = FXCollections.observableArrayList();

    private final ComboBox<String> modeBox = new ComboBox<>(FXCollections.observableArrayList(
            "Direct (java.net.http)", "Burp extension (loopback)"));
    private final ComboBox<String> caseBox;
    private final TextField urlField = new TextField("https://192.0.2.1/resource");
    private final PasswordField tokenField = new PasswordField();
    private final CheckBox dryRunBox = new CheckBox("Dry-run (draft mutations, never transmit)");
    private final TextField maxRequestsField = new TextField("20");
    private final TextField delayField = new TextField("250");
    private final ProgressBar progress = new ProgressBar(0);
    private final Label statusLabel = new Label("Ready");
    private final Label pairingLabel = new Label();
    private final Map<Severity, Label> counters = new EnumMap<>(Severity.class);
    private final TableView<FindingRow> table = new TableView<>();
    private Stage ownerStage;

    public DashboardPanel(TestCaseEngine engine, SessionState session, Runnable onDataChanged) {
        this.engine = engine;
        this.session = session;
        this.onDataChanged = onDataChanged;
        this.caseBox = new ComboBox<>(FXCollections.observableArrayList(engine.availableIds()));
    }

    public Node node() {
        BorderPane root = new BorderPane();
        root.setTop(buildControls());
        root.setCenter(buildTable());
        root.setBottom(buildStatusBar());

        modeBox.getSelectionModel().select(0);
        caseBox.getSelectionModel().select(0);
        dryRunBox.setSelected(true);
        refreshPairingLabel();
        updateCounters();
        return root;
    }

    public void setOwnerStage(Stage stage) {
        this.ownerStage = stage;
    }

    public void applyProfile(TestProfile profile) {
        if (profile.testCaseIds() != null && !profile.testCaseIds().isEmpty()) {
            String id = profile.testCaseIds().get(0);
            if (engine.availableIds().contains(id)) {
                caseBox.getSelectionModel().select(id);
            }
        }
        dryRunBox.setSelected(profile.dryRun());
        maxRequestsField.setText(String.valueOf(profile.maxRequests()));
        delayField.setText(String.valueOf(profile.interRequestDelayMillis()));
        if (profile.tokens() != null && !profile.tokens().isEmpty()) {
            tokenField.setText(profile.tokens().get(0));
        }
        statusLabel.setText("Applied profile: " + profile.name());
    }

    private Node buildControls() {
        GridPane grid = new GridPane();
        grid.setHgap(8);
        grid.setVgap(6);
        grid.setPadding(new Insets(10));
        grid.add(new Label("Run mode"), 0, 0);
        grid.add(modeBox, 1, 0);
        grid.add(new Label("Test case"), 0, 1);
        grid.add(caseBox, 1, 1);
        grid.add(new Label("Target URL"), 0, 2);
        grid.add(urlField, 1, 2);
        GridPane.setHgrow(urlField, Priority.ALWAYS);
        grid.add(new Label("Bearer token"), 0, 3);
        grid.add(tokenField, 1, 3);
        GridPane.setHgrow(tokenField, Priority.ALWAYS);
        grid.add(dryRunBox, 1, 4);
        grid.add(new Label("Max requests"), 0, 5);
        grid.add(maxRequestsField, 1, 5);
        grid.add(new Label("Delay (ms)"), 0, 6);
        grid.add(delayField, 1, 6);

        Button runButton = new Button("Run test case");
        runButton.setDefaultButton(true);
        runButton.setOnAction(e -> run());
        Button clearButton = new Button("Clear");
        clearButton.setOnAction(e -> {
            rows.clear();
            session.clear();
            statusLabel.setText("Cleared");
            progress.setProgress(0);
            onDataChanged.run();
        });

        HBox buttons = new HBox(8, runButton, clearButton);
        grid.add(buttons, 1, 7);
        grid.add(buildCounters(), 1, 8);
        return grid;
    }

    private Node buildCounters() {
        HBox chips = new HBox(8);
        chips.setAlignment(Pos.CENTER_LEFT);
        for (Severity severity : Severity.values()) {
            Label chip = new Label(severity.name() + " 0");
            chip.setStyle("-fx-background-color:" + color(severity) + "; -fx-text-fill:#fff;"
                    + " -fx-background-radius:10; -fx-padding:2 10; -fx-font-weight:bold;");
            counters.put(severity, chip);
            chips.getChildren().add(chip);
        }
        chips.getChildren().add(new Label("(live severity counters)"));
        return chips;
    }

    private Node buildTable() {
        TableColumn<FindingRow, String> severityCol = new TableColumn<>("Severity");
        severityCol.setCellValueFactory(c -> FindingRow.text(c.getValue().severity()));
        severityCol.setPrefWidth(90);
        TableColumn<FindingRow, String> cvssCol = new TableColumn<>("CVSS-like");
        cvssCol.setCellValueFactory(c -> FindingRow.text(c.getValue().cvss()));
        cvssCol.setPrefWidth(80);
        TableColumn<FindingRow, String> stepCol = new TableColumn<>("Step");
        stepCol.setCellValueFactory(c -> FindingRow.text(c.getValue().stepId()));
        stepCol.setPrefWidth(60);
        TableColumn<FindingRow, String> sentCol = new TableColumn<>("Mode");
        sentCol.setCellValueFactory(c -> FindingRow.text(c.getValue().sent()));
        sentCol.setPrefWidth(80);
        TableColumn<FindingRow, String> titleCol = new TableColumn<>("Finding");
        titleCol.setCellValueFactory(c -> FindingRow.text(c.getValue().title()));
        titleCol.setPrefWidth(300);
        TableColumn<FindingRow, String> timeCol = new TableColumn<>("Time");
        timeCol.setCellValueFactory(c -> FindingRow.text(c.getValue().timestamp()));
        timeCol.setPrefWidth(80);
        table.getColumns().addAll(severityCol, cvssCol, stepCol, sentCol, titleCol, timeCol);
        table.setItems(rows);
        table.setPlaceholder(new Label("No findings yet"));
        return table;
    }

    private Node buildStatusBar() {
        HBox bar = new HBox(12, statusLabel, progress, pairingLabel);
        progress.setPrefWidth(180);
        bar.setPadding(new Insets(6, 10, 6, 10));
        bar.setAlignment(Pos.CENTER_LEFT);
        return bar;
    }

    private void run() {
        String url = urlField.getText().trim();
        String token = tokenField.getText().trim();
        String caseId = caseBox.getValue();
        if (url.isEmpty() || token.isEmpty() || caseId == null) {
            statusLabel.setText("URL, token and test case are required");
            return;
        }
        boolean dryRun = dryRunBox.isSelected();
        int maxRequests = parsePositiveInt(maxRequestsField.getText(), 20);
        long delay = parsePositiveLong(delayField.getText(), 250L);
        rows.clear();
        session.clear();
        session.addSecret(token);
        onDataChanged.run();

        boolean loopback = modeBox.getSelectionModel().getSelectedIndex() == 1;
        if (loopback) {
            runThroughBurp(url, token, caseId, dryRun, maxRequests, delay);
        } else {
            runDirect(url, token, caseId, dryRun, maxRequests, delay);
        }
    }

    private void runDirect(String url, String token, String caseId, boolean dryRun, int maxRequests, long delay) {
        statusLabel.setText("Running " + caseId + " directly against " + url);
        progress.setProgress(-1);
        new Thread(() -> {
            try {
                TestProfile profile = new TestProfile("gui-direct", "Direct run",
                        dryRun, maxRequests, delay, List.of(caseId), List.of(token));
                FacadeRequest target = Requests.simpleGet(url, token);
                List<Finding> findings = Runner.run(engine, caseId, profile, target,
                        new DirectHttpFacade(), this::status, stream -> { });
                Platform.runLater(() -> {
                    findings.forEach(f -> rows.add(new FindingRow(f)));
                    findings.forEach(session::add);
                    statusLabel.setText("Completed " + findings.size() + " findings");
                    progress.setProgress(1.0);
                    onDataChanged.run();
                });
            } catch (Exception e) {
                status("Run failed: " + e);
                Platform.runLater(() -> progress.setProgress(1.0));
            }
        }).start();
    }

    private void runThroughBurp(String url, String token, String caseId, boolean dryRun, int maxRequests, long delay) {
        statusLabel.setText("Running " + caseId + " through the Burp extension (loopback)");
        progress.setProgress(-1);
        new Thread(() -> {
            try {
                PairingClient.PairingInfo pairing = PairingClient.loadPairing();
                TestProfile profile = new TestProfile("gui-loopback", "Loopback run",
                        dryRun, maxRequests, delay, List.of(caseId), List.of(token));
                PairingClient.run(pairing, caseId, Profiles.toMap(profile), url, message -> {
                    String kind = String.valueOf(message.get("kind"));
                    if ("finding".equals(kind)) {
                        Finding finding = Runner.fromMap(castMap(message.get("finding")));
                        Platform.runLater(() -> {
                            rows.add(new FindingRow(finding));
                            session.add(finding);
                        });
                    } else if ("done".equals(kind)) {
                        session.setAuditChainHash(String.valueOf(message.get("auditChainHash")));
                        Platform.runLater(() -> {
                            statusLabel.setText("Run complete; audit chain " + session.auditChainHash());
                            progress.setProgress(1.0);
                            refreshPairingLabel();
                            onDataChanged.run();
                        });
                    } else if ("error".equals(kind)) {
                        Platform.runLater(() -> {
                            statusLabel.setText("Extension returned: " + message.get("message"));
                            progress.setProgress(1.0);
                        });
                    } else if ("status".equals(kind)) {
                        status(String.valueOf(message.get("message")));
                    }
                });
            } catch (IOException e) {
                Platform.runLater(() -> {
                    statusLabel.setText("Loopback failure: " + e.getMessage());
                    progress.setProgress(1.0);
                });
            }
        }).start();
    }

    public void updateCounters() {
        Map<Severity, Integer> counts = ReportBuilder.count(session.snapshot());
        for (Severity severity : Severity.values()) {
            Label chip = counters.get(severity);
            if (chip != null) {
                chip.setText(severity.name() + " " + counts.getOrDefault(severity, 0));
            }
        }
    }

    private void refreshPairingLabel() {
        if (!Files.exists(LoopbackControlServer.pairingFile())) {
            pairingLabel.setText("Not paired - load the extension in Burp Suite first");
            return;
        }
        try {
            PairingClient.PairingInfo info = PairingClient.loadPairing();
            pairingLabel.setText("Paired: 127.0.0.1:" + info.port() + " (token masked)");
        } catch (IOException e) {
            pairingLabel.setText("Pairing file unreadable: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    private static String color(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "#d9534f";
            case HIGH -> "#f0ad4e";
            case MEDIUM -> "#d4c100";
            case LOW -> "#5bc0de";
            case INFO -> "#6c757d";
        };
    }

    private void status(String message) {
        Platform.runLater(() -> statusLabel.setText(message));
    }

    private static int parsePositiveInt(String value, int fallback) {
        try {
            int parsed = Integer.parseInt(value.trim());
            return Math.max(1, parsed);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static long parsePositiveLong(String value, long fallback) {
        try {
            long parsed = Long.parseLong(value.trim());
            return Math.max(1, parsed);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}