package com.acs.burptester.core;

import com.acs.burptester.api.Finding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

public final class AuditLog {

    private final String chainAnchor;
    private String lastHash;
    private final StringBuilder jsonLines = new StringBuilder();

    public AuditLog(String buildAnchor) {
        this.chainAnchor = buildAnchor;
        this.lastHash = sha256OrNull(chainAnchor);
    }

    public static AuditLog withAnchor(String anchor) {
        return new AuditLog(anchor);
    }

    public synchronized String record(Finding finding) {
        long ts = System.currentTimeMillis();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("ts", ts);
        entry.put("findingId", finding.id());
        entry.put("wstgId", finding.wstgId());
        entry.put("stepId", finding.stepId());
        entry.put("severity", finding.severity().name());
        entry.put("sent", finding.sent());
        entry.put("title", finding.title());
        String payload = TextJson.stringify(entry);
        String hash = Hashes.chainHash(lastHash == null ? "" : lastHash, ts, payload);
        entry.put("chainHash", hash);
        entry.put("chainPrev", lastHash == null ? "" : lastHash);
        lastHash = hash;
        jsonLines.append(TextJson.stringify(entry)).append('\n');
        return hash;
    }

    public synchronized String lastChainHash() {
        return lastHash;
    }

    public synchronized String payload() {
        return jsonLines.toString();
    }

    public synchronized void writeTo(Path file) throws IOException {
        Files.createDirectories(file.getParent() == null ? Path.of(".") : file.getParent());
        Files.writeString(file, jsonLines.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE);
    }

    private static String sha256OrNull(String s) {
        if (s == null) {
            return null;
        }
        return Hashes.sha256(s);
    }
}