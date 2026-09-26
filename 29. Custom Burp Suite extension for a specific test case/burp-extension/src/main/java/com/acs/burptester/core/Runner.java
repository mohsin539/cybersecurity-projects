package com.acs.burptester.core;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.Finding;
import com.acs.burptester.api.HttpFacade;
import com.acs.burptester.api.TestCaseContext;
import com.acs.burptester.api.TestProfile;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public final class Runner {

    public static final String BUILD_ANCHOR = "BurpTester-build-anchor";

    private Runner() {
    }

    public static List<Finding> run(TestCaseEngine engine, String testCaseId, TestProfile profile,
                                    FacadeRequest target, HttpFacade http, Consumer<String> onProgress,
                                    Consumer<Map<String, Object>> onStream) {
        AuditLog audit = new AuditLog(BUILD_ANCHOR + ":" + engine.hashCode());
        SafeExecutionSandbox sandbox = new SafeExecutionSandbox(profile.dryRun(), profile.maxRequests(),
                profile.interRequestDelayMillis());
        TestCaseContext ctx = new TestCaseContext(profile, target, http, audit, profile.tokens(), onProgress, sandbox);
        List<Finding> findings = engine.run(testCaseId, ctx);
        if (onStream != null) {
            for (Finding finding : findings) {
                Map<String, Object> stream = new LinkedHashMap<>();
                stream.put("kind", "finding");
                stream.put("finding", findingToMap(finding));
                onStream.accept(stream);
            }
            Map<String, Object> done = new LinkedHashMap<>();
            done.put("kind", "done");
            done.put("auditChainHash", audit.lastChainHash());
            done.put("auditPayload", audit.payload());
            onStream.accept(done);
        }
        return findings;
    }

    public static Map<String, Object> findingToMap(Finding finding) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", finding.id());
        map.put("wstgId", finding.wstgId());
        map.put("severity", finding.severity().name());
        map.put("cvssLike", finding.cvssLike());
        map.put("title", finding.title());
        map.put("stepId", finding.stepId());
        map.put("evidence", finding.evidence());
        map.put("remediation", finding.remediation());
        map.put("sent", finding.sent());
        return map;
    }

    public static Finding fromMap(Map<String, Object> map) {
        return new Finding(
                strVal(map.get("id")),
                strVal(map.get("wstgId")),
                com.acs.burptester.api.Severity.valueOf(strVal(map.get("severity"))),
                doubleVal(map.get("cvssLike")),
                strVal(map.get("title")),
                strVal(map.get("stepId")),
                strVal(map.get("evidence")),
                strVal(map.get("remediation")),
                Boolean.TRUE.equals(map.get("sent")));
    }

    private static String strVal(Object value) {
        if (value == null) {
            return "";
        }
        String s = String.valueOf(value);
        if ("null".equals(s)) {
            return "";
        }
        return s.replace("\"", "");
    }

    private static double doubleVal(Object value) {
        if (value instanceof Number n) {
            return n.doubleValue();
        }
        if (value instanceof String s) {
            try {
                return Double.parseDouble(s.trim());
            } catch (NumberFormatException e) {
                return 0.0;
            }
        }
        return 0.0;
    }
}