package com.acs.launcher.ui;

import com.acs.burptester.api.TestProfile;
import com.acs.burptester.core.Hashes;
import com.acs.burptester.core.Profiles;
import com.acs.burptester.core.TestCaseEngine;
import com.acs.burptester.core.TextJson;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class ConfigEditorPanel {

    private final TextField idField = new TextField("default");
    private final TextField nameField = new TextField("Default BurpTester profile");
    private final CheckBox dryRunBox = new CheckBox("Dry-run by default (safe for active payloads)");
    private final TextField maxRequestsField = new TextField("20");
    private final TextField delayField = new TextField("250");
    private final PasswordField tokenField = new PasswordField();
    private final Label hashLabel = new Label();
    private final Label statusField = new Label();
    private final List<CheckBox> caseChecks = new ArrayList<>();
    private final List<String> availableCases;
    private final Consumer<TestProfile> onApply;
    private Path lastFile;
    private Stage ownerStage;

    public ConfigEditorPanel(TestCaseEngine engine, Consumer<TestProfile> onApply) {
        this.availableCases = engine.availableIds();
        this.onApply = onApply;
    }

    public Node node() {
        GridPane grid = new GridPane();
        grid.setHgap(8);
        grid.setVgap(6);
        grid.setPadding(new Insets(10));

        int row = 0;
        grid.add(new Label("Profile ID"), 0, row);
        grid.add(idField, 1, row++);
        GridPane.setHgrow(idField, Priority.ALWAYS);
        grid.add(new Label("Profile name"), 0, row);
        grid.add(nameField, 1, row++);
        GridPane.setHgrow(nameField, Priority.ALWAYS);
        grid.add(new Label("Policy"), 0, row);
        grid.add(dryRunBox, 1, row++);
        grid.add(new Label("Max requests"), 0, row);
        grid.add(maxRequestsField, 1, row++);
        grid.add(new Label("Delay (ms)"), 0, row);
        grid.add(delayField, 1, row++);
        grid.add(new Label("Bearer token (in-memory)"), 0, row);
        grid.add(tokenField, 1, row++);
        GridPane.setHgrow(tokenField, Priority.ALWAYS);

        Label casesLabel = new Label("Test cases");
        VBox caseBox = new VBox(4);
        for (String caseId : availableCases) {
            CheckBox check = new CheckBox(caseId);
            check.setSelected(caseId.equals(availableCases.get(0)));
            caseChecks.add(check);
            caseBox.getChildren().add(check);
        }
        grid.add(casesLabel, 0, row);
        grid.add(caseBox, 1, row++);

        Button loadButton = new Button("Load profile...");
        loadButton.setOnAction(e -> loadProfile());
        Button saveButton = new Button("Save profile...");
        saveButton.setOnAction(e -> saveProfile());
        Button applyButton = new Button("Apply to Run");
        applyButton.setOnAction(e -> {
            onApply.accept(currentProfile());
            refreshHash();
        });
        Button hashButton = new Button("Refresh SHA-256");
        hashButton.setOnAction(e -> refreshHash());

        HBox actions = new HBox(8, loadButton, saveButton, applyButton, hashButton);
        grid.add(actions, 1, row++);

        VBox bottom = new VBox(6,
                hashLabel,
                statusField,
                new Label("Note: bearer tokens are held in memory only and are never written to the profile file (secrets never persist, per architecture ADR-1 / Threat model T-8)."));

        VBox root = new VBox(12, grid, bottom);
        root.setPadding(new Insets(4));
        refreshHash();
        return root;
    }

    public void setOwnerStage(Stage stage) {
        this.ownerStage = stage;
    }

    public TestProfile currentProfile() {
        return new TestProfile(
                idField.getText().trim(),
                nameField.getText().trim(),
                dryRunBox.isSelected(),
                parsePositiveInt(maxRequestsField.getText(), 20),
                parsePositiveLong(delayField.getText(), 250L),
                checkedCases(),
                tokenField.getText().isBlank() ? List.of() : List.of(tokenField.getText().trim()));
    }

    private List<String> checkedCases() {
        return caseChecks.stream().filter(CheckBox::isSelected)
                .map(c -> c.getText().trim()).toList();
    }

    private void refreshHash() {
        hashLabel.setText("SHA-256 (signable profile artifact): " + Hashes.sha256(profileJsonForDisk()));
    }

    private String profileJsonForDisk() {
        TestProfile profile = currentProfile();
        TestProfile withoutTokens = new TestProfile(profile.id(), profile.name(), profile.dryRun(),
                profile.maxRequests(), profile.interRequestDelayMillis(), profile.testCaseIds(), List.of());
        return TextJson.stringify(Profiles.toMap(withoutTokens));
    }

    private void loadProfile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Load BurpTester profile");
        var file = chooser.showOpenDialog(ownerStage);
        if (file == null) {
            return;
        }
        try {
            String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            TestProfile profile = Profiles.fromJson(json);
            idField.setText(profile.id());
            nameField.setText(profile.name());
            dryRunBox.setSelected(profile.dryRun());
            maxRequestsField.setText(String.valueOf(profile.maxRequests()));
            delayField.setText(String.valueOf(profile.interRequestDelayMillis()));
            for (CheckBox check : caseChecks) {
                check.setSelected(profile.testCaseIds().contains(check.getText().trim()));
            }
            lastFile = file.toPath();
            refreshHash();
            statusField.setText("Loaded " + file.getName() + " (token field left empty - never persisted)");
        } catch (IOException | IllegalArgumentException e) {
            statusField.setText("Load failed: " + e.getMessage());
        }
    }

    private void saveProfile() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save BurpTester profile");
        if (lastFile != null) {
            chooser.setInitialFileName(lastFile.getFileName().toString());
        } else {
            chooser.setInitialFileName("profile.json");
        }
        var file = chooser.showSaveDialog(ownerStage);
        if (file == null) {
            return;
        }
        try {
            Files.writeString(file.toPath(), profileJsonForDisk(), StandardCharsets.UTF_8);
            lastFile = file.toPath();
            refreshHash();
            statusField.setText("Saved " + file.getName() + " (tokens excluded; hash " + Hashes.sha256(profileJsonForDisk()) + ")");
        } catch (IOException e) {
            statusField.setText("Save failed: " + e.getMessage());
        }
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