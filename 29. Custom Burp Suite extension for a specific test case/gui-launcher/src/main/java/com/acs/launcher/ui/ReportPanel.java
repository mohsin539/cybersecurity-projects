package com.acs.launcher.ui;

import com.acs.burptester.api.Finding;
import com.acs.burptester.core.AuditLog;
import com.acs.launcher.core.SessionState;
import com.acs.launcher.report.Redactor;
import com.acs.launcher.report.ReportBuilder;
import com.acs.launcher.report.ZipPack;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ReportPanel {

    private final SessionState session;
    private final Label summaryLabel = new Label("No findings yet");
    private final TextArea preview = new TextArea();
    private Stage ownerStage;

    public ReportPanel(SessionState session) {
        this.session = session;
        preview.setEditable(false);
        preview.setWrapText(true);
        preview.setPromptText("Generate a report or select an export above; the artifact content is previewed here.");
    }

    public Node node() {
        Button ndjsonButton = new Button("Export NDJSON");
        ndjsonButton.setOnAction(e -> export(ExportKind.NDJSON));
        Button htmlButton = new Button("Export HTML");
        htmlButton.setOnAction(e -> export(ExportKind.HTML));
        Button csvButton = new Button("Export CSV evidence");
        csvButton.setOnAction(e -> export(ExportKind.CSV));
        Button auditButton = new Button("Export audit log");
        auditButton.setOnAction(e -> export(ExportKind.AUDIT));
        Button zipButton = new Button("Export evidence ZIP");
        zipButton.setOnAction(e -> export(ExportKind.ZIP));

        HBox actions = new HBox(8, ndjsonButton, htmlButton, csvButton, auditButton, zipButton);
        actions.setAlignment(Pos.CENTER_LEFT);

        VBox root = new VBox(10, summaryLabel, actions, preview);
        VBox.setVgrow(preview, Priority.ALWAYS);
        root.setPadding(new Insets(10));
        refreshSummary();
        return root;
    }

    public void setOwnerStage(Stage stage) {
        this.ownerStage = stage;
    }

    public void refreshSummary() {
        var counts = ReportBuilder.count(session.snapshot());
        String hash = session.auditChainHash();
        summaryLabel.setText("Session findings: " + session.snapshot().size()
                + " (CRITICAL " + counts.getOrDefault(com.acs.burptester.api.Severity.CRITICAL, 0)
                + " / HIGH " + counts.getOrDefault(com.acs.burptester.api.Severity.HIGH, 0)
                + " / MEDIUM " + counts.getOrDefault(com.acs.burptester.api.Severity.MEDIUM, 0)
                + " / LOW " + counts.getOrDefault(com.acs.burptester.api.Severity.LOW, 0)
                + " / INFO " + counts.getOrDefault(com.acs.burptester.api.Severity.INFO, 0)
                + ")  |  audit chain: " + (hash.isEmpty() ? "-" : hash));
    }

    private void export(ExportKind kind) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(kind.title);
        switch (kind) {
            case NDJSON -> chooser.setInitialFileName("findings.ndjson");
            case HTML -> chooser.setInitialFileName("burptester-report.html");
            case CSV -> chooser.setInitialFileName("evidence.csv");
            case AUDIT -> chooser.setInitialFileName("audit.ndjson");
            case ZIP -> chooser.setInitialFileName("burptester-evidence.zip");
        }
        var file = chooser.showSaveDialog(ownerStage);
        if (file == null) {
            return;
        }
        try {
            Path target = file.toPath();
            switch (kind) {
                case NDJSON -> {
                    Files.writeString(target, session.findingsJsonLines(), StandardCharsets.UTF_8);
                    preview.setText("Written " + session.snapshot().size() + " NDJSON records -> " + target);
                }
                case HTML -> {
                    String html = redacted(ReportBuilder.html("BurpTester Security Report",
                            session.snapshot(), session.auditChainHash(), runInfo()));
                    Files.writeString(target, html, StandardCharsets.UTF_8);
                    preview.setText(html);
                }
                case CSV -> {
                    String csv = redacted(ReportBuilder.csv(session.snapshot()));
                    Files.writeString(target, csv, StandardCharsets.UTF_8);
                    preview.setText(csv);
                }
                case AUDIT -> {
                    String payload = redacted(auditPayload());
                    Files.writeString(target, payload, StandardCharsets.UTF_8);
                    preview.setText(payload);
                }
                case ZIP -> {
                    byte[] bytes = redactedZip();
                    Files.write(target, bytes);
                    preview.setText("Produced evidence ZIP at " + target + " (findings.ndjson, report.html, evidence.csv, audit.ndjson, SHA256SUMS.txt)");
                }
            }
            summaryLabel.setText(summaryLabel.getText() + "   -> exported: " + target);
        } catch (IOException e) {
            summaryLabel.setText("Export failed: " + e.getMessage());
        }
    }

    private String runInfo() {
        return "BurpTester portable launcher (gui " + guiVersion() + ") - WSTG-SESS-10";
    }

    private String guiVersion() {
        Package pkg = ReportPanel.class.getPackage();
        return pkg == null || pkg.getImplementationVersion() == null ? "dev" : pkg.getImplementationVersion();
    }

    private String redacted(String text) {
        return Redactor.redact(session.secrets(), text);
    }

    private String auditPayload() {
        AuditLog log = new AuditLog("gui-session");
        session.snapshot().forEach(log::record);
        return log.payload();
    }

    private byte[] redactedZip() throws IOException {
        java.util.List<Finding> findings = session.snapshot();
        java.util.List<ZipPack.Entry> entries = new java.util.ArrayList<>();
        entries.add(new ZipPack.Entry("findings.ndjson",
                redacted(session.findingsJsonLines()).getBytes(StandardCharsets.UTF_8)));
        entries.add(new ZipPack.Entry("report.html",
                redacted(ReportBuilder.html("BurpTester Security Report", findings,
                        session.auditChainHash(), runInfo())).getBytes(StandardCharsets.UTF_8)));
        entries.add(new ZipPack.Entry("evidence.csv",
                redacted(ReportBuilder.csv(findings)).getBytes(StandardCharsets.UTF_8)));
        entries.add(new ZipPack.Entry("audit.ndjson",
                redacted(auditPayload()).getBytes(StandardCharsets.UTF_8)));
        return ZipPack.archive(entries);
    }

    private enum ExportKind {
        NDJSON("Export findings as NDJSON"),
        HTML("Export OWASP-style HTML report"),
        CSV("Export CSV evidence"),
        AUDIT("Export hash-chained audit log"),
        ZIP("Export evidence ZIP pack");

        final String title;

        ExportKind(String title) {
            this.title = title;
        }
    }
}