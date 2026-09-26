package com.acs.burptester.api;

import java.util.List;

public record TestProfile(
        String id,
        String name,
        boolean dryRun,
        int maxRequests,
        long interRequestDelayMillis,
        List<String> testCaseIds,
        List<String> tokens) {

    public TestProfile {
        testCaseIds = testCaseIds == null ? List.of() : List.copyOf(testCaseIds);
        tokens = tokens == null ? List.of() : List.copyOf(tokens);
    }
}