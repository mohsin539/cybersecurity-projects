package com.acs.launcher.report;

import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportBuilderTest {

    private static final Finding HIGH = new Finding("SESS-10-S2", "WSTG-SESS-10", Severity.HIGH, 8.1,
            "alg none accepted", "S2", "GET /admin 200 Authorization: Bearer eyJstuff",
            "Reject alg none", true);
    private static final Finding INFO = new Finding("SESS-10-S1", "WSTG-SESS-10", Severity.INFO, 0.0,
            "token parsed, alg=RS256", "S1", "header.alg = RS256", "Restrict alg allowlist", false);

    @Test
    void csvEscapesQuotesAndCommas() {
        Finding tricky = new Finding("T", "WSTG-SESS-10", Severity.MEDIUM, 3.0,
                "title, with, commas", "S2", "evidence \"quoted\" here", "fix \"it\"", false);
        String csv = ReportBuilder.csv(List.of(tricky));
        assertTrue(csv.contains("\"title, with, commas\""));
        assertTrue(csv.contains("\"evidence \"\"quoted\"\" here\""));
        assertTrue(csv.startsWith("severity,cvss,wstgId,stepId,mode,title,evidence,remediation"));
    }

    @Test
    void htmlContainsSummaryCountsWstgAndAuditHash() {
        String html = ReportBuilder.html("Test report", List.of(HIGH, INFO), "abc123", "unit run");
        assertTrue(html.contains("<title>Test report</title>"));
        assertTrue(html.contains("HIGH</span> 1"));
        assertTrue(html.contains("WSTG-SESS-10"));
        assertTrue(html.contains("abc123"));
        assertTrue(html.contains("alg none accepted"));
    }

    @Test
    void htmlEscapesMarkupInEvidence() {
        Finding xss = new Finding("X", "WSTG-SESS-10", Severity.LOW, 1.0,
                "<script>alert(1)</script>", "S4", "body &amp; payload", "sanitize", false);
        String html = ReportBuilder.html("r", List.of(xss), "", "");
        assertFalse(html.contains("<script>alert"));
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    @Test
    void redactorReplacesSecrets() {
        String out = Redactor.redact(List.of("superSecretToken"), "Bearer superSecretToken accepted");
        assertEquals("Bearer [REDACTED] accepted", out);
    }

    @Test
    void zipContainsManifestWithHashes() throws Exception {
        byte[] bytes = ZipPack.archive(
                new ZipPack.Entry("a.txt", "hello".getBytes(StandardCharsets.UTF_8)),
                new ZipPack.Entry("b.txt", "world".getBytes(StandardCharsets.UTF_8)));
        ByteArrayOutputStream names = new ByteArrayOutputStream();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            int dataEntries = 0;
            boolean manifest = false;
            while ((entry = zip.getNextEntry()) != null) {
                names.write((entry.getName() + "\n").getBytes(StandardCharsets.UTF_8));
                if ("SHA256SUMS.txt".equals(entry.getName())) {
                    manifest = true;
                } else {
                    dataEntries++;
                }
                zip.closeEntry();
            }
            assertEquals(2, dataEntries);
            assertTrue(manifest);
        }
    }
}