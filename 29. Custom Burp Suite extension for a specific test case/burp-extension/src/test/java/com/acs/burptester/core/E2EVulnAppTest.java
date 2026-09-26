package com.acs.burptester.core;

import com.acs.burptester.api.Finding;
import com.acs.burptester.api.TestProfile;
import com.acs.burptester.modules.jwt.JwtTokenTestPack;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfEnvironmentVariable(named = "BURPTESTER_E2E", matches = "1")
class E2EVulnAppTest {

    private static final String URL = System.getenv().getOrDefault("BURPTESTER_E2E_URL", "http://127.0.0.1:8765/resource");

    @Test
    void algNoneIsDetectedAgainstVulnerableFixture() {
        TestCaseEngine engine = new TestCaseEngine().register(new JwtTokenTestPack());
        String header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"RS256","typ":"JWT"}
        String payload = "eyJzdWIiOiJhZG1pbiIsImV4cCI6OTAwMDAwMDAwMH0"; // {"sub":"admin","exp":9000000000}
        String token = header + "." + payload + ".signature";

        TestProfile profile = new TestProfile("e2e", "E2E", false, 30, 0L, List.of(), List.of("dummy"));
        com.acs.burptester.api.TestCaseContext ctx = new com.acs.burptester.api.TestCaseContext(profile,
                Requests.simpleGet(URL, token), new DirectHttpFacade(), new AuditLog("e2e"), List.of("dummy"), null,
                new SafeExecutionSandbox(false, 30, 0L));

        List<Finding> findings = engine.run("WSTG-SESS-10", ctx);
        boolean algNoneHigh = findings.stream().anyMatch(f ->
                "S2".equals(f.stepId()) && f.severity() == com.acs.burptester.api.Severity.HIGH);
        assertTrue(algNoneHigh, "vuln-app accepts alg=none; engine must raise HIGH finding. Got: " + findings);
    }
}