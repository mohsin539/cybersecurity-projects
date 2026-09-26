package com.acs.burptester.api;

public record Finding(
        String id,
        String wstgId,
        Severity severity,
        double cvssLike,
        String title,
        String stepId,
        String evidence,
        String remediation,
        boolean sent) {

    public Finding withSent(boolean sentValue) {
        return new Finding(id, wstgId, severity, cvssLike, title, stepId, evidence, remediation, sentValue);
    }
}