package com.acs.burptester.core;

import com.acs.burptester.api.TestProfile;
import com.acs.burptester.modules.jwt.JwtInspector;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoreLogicTest {

    @Test
    void textJsonRoundTrip() {
        Map<String, Object> map = TextJson.parseObject("{\"a\":1,\"b\":\"x\",\"c\":true,\"d\":[1,2]}");
        assertEquals(1L, map.get("a"));
        assertEquals("x", map.get("b"));
        assertEquals(Boolean.TRUE, map.get("c"));
        assertEquals(2, ((List<?>) map.get("d")).size());
        String out = TextJson.stringify(map);
        assertTrue(out.contains("\"a\":1"));
    }

    @Test
    void jwtParseRecognisesParts() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
                + "eyJzdWIiOiJhZG1pbiIsImV4cCI6OTAwMDAwMDAwMH0.signature";
        var parsed = JwtInspector.parse(token);
        assertTrue(parsed.isPresent());
        assertEquals("RS256", parsed.get().alg());
        assertEquals("JWT", parsed.get().typ());
        assertEquals(9000000000L, parsed.get().exp());
        assertEquals("admin", parsed.get().payloadClaims().get("sub"));
    }

    @Test
    void dryRunBlocksDestructiveStepsAtBoundary() {
        TestCaseEngine engine = new TestCaseEngine().register(new com.acs.burptester.modules.jwt.JwtTokenTestPack());
        TestProfile profile = new TestProfile("t", "dry-run", true, 5, 0, List.of(), List.of());
        var ctx = new com.acs.burptester.api.TestCaseContext(profile,
                com.acs.burptester.core.Requests.simpleGet("https://example.test/", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.sig"),
                new DirectHttpFacade(), new AuditLog("test"), List.of(), null, new SafeExecutionSandbox(true, 5, 0));
        var findings = engine.run("WSTG-SESS-10", ctx);
        boolean blocked = findings.stream().anyMatch(f -> f.id().equals("BOUNDARY"));
        assertTrue(blocked, "dry-run must halt destructive steps");
    }

    @Test
    void auditChainIsDigestDependent() {
        AuditLog log = new AuditLog("anchor");
        String first = log.record(new com.acs.burptester.api.Finding("A", "WSTG", com.acs.burptester.api.Severity.LOW,
                1.0, "t1", "S1", "e", "r", false));
        String second = log.record(new com.acs.burptester.api.Finding("B", "WSTG", com.acs.burptester.api.Severity.HIGH,
                8.0, "t2", "S2", "e", "r", true));
        assertNotEquals(first, second);
        assertEquals(second, log.lastChainHash());
    }
}