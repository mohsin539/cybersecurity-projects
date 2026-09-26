package com.acs.launcher.report;

import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public final class ReportBuilder {

    private ReportBuilder() {
    }

    public static Map<Severity, Integer> count(List<Finding> findings) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Finding finding : findings) {
            counts.merge(finding.severity(), 1, Integer::sum);
        }
        return counts;
    }

    public static String csv(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("severity,cvss,wstgId,stepId,mode,title,evidence,remediation\n");
        for (Finding finding : findings) {
            sb.append(escCsv(finding.severity().name())).append(',');
            sb.append(escCsv(String.format("%.1f", finding.cvssLike()))).append(',');
            sb.append(escCsv(finding.wstgId())).append(',');
            sb.append(escCsv(finding.stepId())).append(',');
            sb.append(finding.sent() ? "sent" : "analysed").append(',');
            sb.append(escCsv(finding.title())).append(',');
            sb.append(escCsv(finding.evidence())).append(',');
            sb.append(escCsv(finding.remediation())).append('\n');
        }
        return sb.toString();
    }

    public static String html(String title, List<Finding> findings, String auditChainHash, String runInfo) {
        Map<Severity, Integer> counts = count(findings);
        StringBuilder rows = new StringBuilder();
        for (Finding finding : findings) {
            rows.append("<tr>")
                    .append("<td><span class=\"badge\" style=\"background:").append(color(finding.severity()))
                    .append(";\">").append(finding.severity().name()).append("</span></td>")
                    .append("<td>").append(String.format("%.1f", finding.cvssLike())).append("</td>")
                    .append("<td>").append(escHtml(finding.wstgId())).append("</td>")
                    .append("<td>").append(escHtml(finding.stepId())).append("</td>")
                    .append("<td>").append(finding.sent() ? "sent" : "analysed").append("</td>")
                    .append("<td>").append(escHtml(finding.title())).append("</td>")
                    .append("<td><pre>").append(escHtml(finding.evidence())).append("</pre></td>")
                    .append("<td>").append(escHtml(finding.remediation())).append("</td>")
                    .append("</tr>\n");
        }

        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                + "<title>" + escHtml(title) + "</title>\n<style>\n"
                + "body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1f23;}\n"
                + "header{background:#0b1f3a;color:#fff;padding:18px 24px;border-radius:6px;}\n"
                + "h1{margin:0;font-size:22px;}h2{font-size:16px;margin-top:28px;}\n"
                + "table{border-collapse:collapse;width:100%;font-size:13px;}\n"
                + "th{background:#eef1f5;text-align:left;padding:7px 9px;border:1px solid #d0d7de;}\n"
                + "td{padding:7px 9px;border:1px solid #d0d7de;vertical-align:top;}\n"
                + "pre{white-space:pre-wrap;word-break:break-all;margin:0;font-size:11px;}\n"
                + ".badge{color:#fff;padding:2px 8px;border-radius:10px;font-weight:600;}\n"
                + ".meta{color:#8b949e;font-size:12px;margin-top:6px;}\n"
                + "footer{margin-top:28px;font-size:11px;color:#57606a;}\n"
                + ".sum{display:inline-block;margin-right:12px;font-weight:600;}\n"
                + "</style>\n</head>\n<body>\n"
                + "<header><h1>" + escHtml(title) + "</h1>"
                + "<div class=\"meta\">Generated " + timestamp() + " &middot; " + escHtml(runInfo) + "</div></header>\n"
                + "<h2>Executive summary</h2>\n<div>"
                + summaryChip(counts.getOrDefault(Severity.CRITICAL, 0), Severity.CRITICAL)
                + summaryChip(counts.getOrDefault(Severity.HIGH, 0), Severity.HIGH)
                + summaryChip(counts.getOrDefault(Severity.MEDIUM, 0), Severity.MEDIUM)
                + summaryChip(counts.getOrDefault(Severity.LOW, 0), Severity.LOW)
                + summaryChip(counts.getOrDefault(Severity.INFO, 0), Severity.INFO)
                + "<span class=\"sum\">Total " + findings.size() + "</span></div>\n"
                + "<h2>Findings</h2>\n<table>\n<thead><tr>"
                + "<th>Severity</th><th>CVSS-like</th><th>WSTG</th><th>Step</th><th>Mode</th>"
                + "<th>Title</th><th>Evidence</th><th>Remediation</th></tr></thead>\n<tbody>\n"
                + rows
                + "</tbody>\n</table>\n"
                + (auditChainHash == null || auditChainHash.isEmpty() ? "" :
                "<h2>Audit provenance</h2>\n<p>Audit chain hash: <code>" + escHtml(auditChainHash) + "</code></p>\n")
                + "<footer>Generated by BurpTester portable launcher (WSTG-SESS-10). "
                + "Evidence is local-only by design and should be reviewed before any external distribution.</footer>\n"
                + "</body>\n</html>\n";
    }

    private static String summaryChip(int count, Severity severity) {
        return "<span class=\"sum\"><span class=\"badge\" style=\"background:" + color(severity)
                + ";\">" + severity.name() + "</span> " + count + "</span>";
    }

    private static String color(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "#d9534f";
            case HIGH -> "#f0ad4e";
            case MEDIUM -> "#f0e26a";
            case LOW -> "#5bc0de";
            case INFO -> "#6c757d";
        };
    }

    private static String escCsv(String value) {
        String s = value == null ? "" : value.replace("\r", " ").replace("\n", " ");
        if (s.indexOf(',') >= 0 || s.indexOf('"') >= 0) {
            return '"' + s.replace("\"", "\"\"") + '"';
        }
        return s;
    }

    private static String escHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String timestamp() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").format(new Date());
    }
}