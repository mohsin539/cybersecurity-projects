package com.acs.burptester.core;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.HttpFacade;
import com.acs.burptester.api.TestProfile;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.List;

public final class BurpTesterSuiteTab extends JPanel {

    private final TestCaseEngine engine;
    private final HttpFacade http;
    private final JTextField urlField = new JTextField("https://target.example/resource", 40);
    private final JTextField tokenField = new JTextField(60);
    private final JCheckBox dryRunBox = new JCheckBox("Dry-run (never mutate traffic)", true);
    private final JTextArea console = new JTextArea(18, 80);

    public BurpTesterSuiteTab(TestCaseEngine engine, HttpFacade http) {
        super(new BorderLayout(8, 8));
        this.engine = engine;
        this.http = http;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(buildControls(), BorderLayout.NORTH);
        console.setEditable(false);
        console.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
        add(new JScrollPane(console), BorderLayout.CENTER);
    }

    private JPanel buildControls() {
        JPanel controls = new JPanel(new BorderLayout(8, 8));
        JPanel fields = new JPanel(new GridLayout(0, 1, 4, 4));
        fields.add(new JLabel("Target URL"));
        fields.add(urlField);
        fields.add(new JLabel("Bearer token"));
        fields.add(tokenField);
        fields.add(dryRunBox);
        JButton runButton = new JButton("Run WSTG-SESS-10 (JWT)");
        runButton.addActionListener(e -> startRun());
        controls.add(fields, BorderLayout.CENTER);
        controls.add(runButton, BorderLayout.EAST);
        return controls;
    }

    private void startRun() {
        String url = urlField.getText().trim();
        String token = tokenField.getText().trim();
        if (url.isEmpty() || token.isEmpty()) {
            append("Provide a target URL and a Bearer token.\n");
            return;
        }
        append("Starting WSTG-SESS-10 against " + url + "\n");
        FacadeRequest target = Requests.simpleGet(url, token);
        TestProfile profile = new TestProfile("suite-tab", "Suite tab run",
                dryRunBox.isSelected(), 20, 250L, List.of("WSTG-SESS-10"), List.of("rsa-key-placeholder"));
        Runnable job = () -> Runner.run(engine, "WSTG-SESS-10", profile, target, http,
                progress -> append(progress + "\n"), stream -> { });
        new Thread(job).start();
    }

    private void append(String text) {
        SwingUtilities.invokeLater(() -> {
            console.append(text);
            console.setCaretPosition(console.getDocument().getLength());
        });
    }
}