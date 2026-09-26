package com.acs.launcher.core;

import com.acs.burptester.api.Finding;
import com.acs.burptester.core.Runner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class SessionState {

    private final List<Finding> findings = new ArrayList<>();
    private final List<String> secrets = new ArrayList<>();
    private String auditChainHash = "";

    public synchronized void add(Finding finding) {
        findings.add(finding);
    }

    public synchronized void addSecret(String secret) {
        if (secret != null && !secret.isBlank() && !secrets.contains(secret)) {
            secrets.add(secret);
        }
    }

    public synchronized List<String> secrets() {
        return List.copyOf(secrets);
    }

    public synchronized void setAuditChainHash(String hash) {
        this.auditChainHash = hash;
    }

    public synchronized String auditChainHash() {
        return auditChainHash;
    }

    public synchronized List<Finding> snapshot() {
        return List.copyOf(findings);
    }

    public synchronized void clear() {
        findings.clear();
        secrets.clear();
        auditChainHash = "";
    }

    public synchronized String findingsJsonLines() {
        StringBuilder sb = new StringBuilder();
        List<Map<String, Object>> maps = snapshot().stream().map(Runner::findingToMap).toList();
        for (Map<String, Object> map : maps) {
            sb.append(com.acs.burptester.core.TextJson.stringify(map)).append('\n');
        }
        return sb.toString();
    }
}