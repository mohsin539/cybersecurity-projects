package com.acs.burptester.core;

import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;
import com.acs.burptester.api.TestCase;
import com.acs.burptester.api.TestCaseContext;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TestCaseEngine {

    private final Map<String, TestCase> cases = new LinkedHashMap<>();

    public TestCaseEngine register(TestCase testCase) {
        cases.put(testCase.id(), testCase);
        return this;
    }

    public List<TestCase> allCases() {
        return List.copyOf(cases.values());
    }

    public List<String> availableIds() {
        return List.copyOf(cases.keySet());
    }

    public TestCase get(String id) {
        return cases.get(id);
    }

    public List<Finding> run(String id, TestCaseContext ctx) {
        TestCase testCase = cases.get(id);
        if (testCase == null) {
            throw new IllegalArgumentException("unknown test case: " + id);
        }
        List<Finding> findings = new ArrayList<>();
        for (var step : testCase.steps()) {
            if (ctx.sandbox.dispatched() >= ctx.profile.maxRequests()) {
                break;
            }
            ctx.onProgress.accept("step " + step.id() + " " + step.description());
            try {
                Finding finding = step.run(ctx);
                if (finding != null) {
                    findings.add(finding);
                    ctx.audit.record(finding);
                }
            } catch (HaltRunException e) {
                findings.add(new Finding("BOUNDARY", testCase.wstgId(), Severity.INFO, 0.0,
                        "Run boundary reached", "sandbox", e.getMessage(),
                        "Increase maxRequests / interRequestDelay when safe, or disable dry-run.", false));
                ctx.audit.record(findings.get(findings.size() - 1));
                break;
            } catch (Exception e) {
                ctx.onProgress.accept("step " + step.id() + " failed: " + e);
            }
        }
        return findings;
    }
}