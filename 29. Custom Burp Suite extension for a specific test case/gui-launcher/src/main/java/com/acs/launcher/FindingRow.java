package com.acs.launcher;

import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;
import javafx.beans.property.ReadOnlyStringWrapper;

import java.text.SimpleDateFormat;
import java.util.Date;

public final class FindingRow {

    private final String severity;
    private final String cvss;
    private final String title;
    private final String stepId;
    private final String evidence;
    private final String sent;
    private final String timestamp;

    public FindingRow(Finding finding) {
        this(finding, new SimpleDateFormat("HH:mm:ss").format(new Date()));
    }

    public FindingRow(Finding finding, String timestamp) {
        this.severity = finding.severity().name();
        this.cvss = String.format("%.1f", finding.cvssLike());
        this.title = finding.title();
        this.stepId = finding.stepId();
        this.evidence = finding.evidence();
        this.sent = finding.sent() ? "sent" : "analysed";
        this.timestamp = timestamp;
    }

    public String severity() {
        return severity;
    }

    public String cvss() {
        return cvss;
    }

    public String title() {
        return title;
    }

    public String stepId() {
        return stepId;
    }

    public String evidence() {
        return evidence;
    }

    public String sent() {
        return sent;
    }

    public String timestamp() {
        return timestamp;
    }

    public static ReadOnlyStringWrapper text(String value) {
        return new ReadOnlyStringWrapper(value);
    }
}