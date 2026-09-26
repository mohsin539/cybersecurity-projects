package com.acs.burptester.modules.jwt;

import com.acs.burptester.api.FacadeRequest;
import com.acs.burptester.api.FacadeResponse;
import com.acs.burptester.api.Finding;
import com.acs.burptester.api.Severity;
import com.acs.burptester.api.TestCase;
import com.acs.burptester.api.TestCaseContext;
import com.acs.burptester.api.TestStep;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class JwtTokenTestPack implements TestCase {

    public static final String ID = "WSTG-SESS-10";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String wstgId() {
        return "WSTG-SESS-10";
    }

    @Override
    public String displayName() {
        return "JWT / JSON Web Token security";
    }

    @Override
    public List<TestStep> steps() {
        List<TestStep> steps = new ArrayList<>();
        steps.add(new SniffStructureStep());
        steps.add(new AlgNoneStep());
        steps.add(new Rs256Hs256Step());
        steps.add(new SignatureStripStep());
        steps.add(new KidPathTraversalStep());
        steps.add(new ExpiryBoundaryStep());
        steps.add(new ReplaySwapStep());
        return steps;
    }

    private static String bearerToken(FacadeRequest request) {
        String auth = request.headerValue("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            return null;
        }
        return auth.substring("Bearer ".length()).trim();
    }

    private static FacadeResponse send(TestCaseContext ctx, FacadeRequest request) {
        ctx.sandbox.authorize("send", false);
        return ctx.http.send(request);
    }

    private static Finding acceptance(TestCaseContext ctx, FacadeRequest sent, FacadeResponse response,
                                     String stepId, String title) {
        boolean accepted = JwtTools.indicatesAcceptance(response.status(), response.bodyText());
        String evidence = stepId + " status=" + response.status()
                + " bodyFingerprint=" + JwtTools.fingerprint(response.body());
        if (accepted) {
            return new Finding(stepId, ID, Severity.HIGH, 8.0, title, stepId, evidence,
                    "Enforce strict token validation: restrict allowed algorithms, verify signatures "
                            + "against a trusted key store, and validate all claims.", true);
        }
        return new Finding(stepId, ID, Severity.INFO, 0.0, title + " - resisted", stepId, evidence,
                "No action required for this test path.", true);
    }

    private static final class SniffStructureStep implements TestStep {
        @Override
        public String id() {
            return "S1";
        }

        @Override
        public String description() {
            return "Parse token header/payload and enumerate weak algorithm declarations";
        }

        @Override
        public boolean destructive() {
            return false;
        }

        @Override
        public Finding run(TestCaseContext ctx) {
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null) {
                return new Finding("S1", ID, Severity.LOW, 2.0, "No JWT supplied",
                        "S1", "Authorization header did not contain a Bearer token.",
                        "Provide a JWT for the target under test.", false);
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return new Finding("S1", ID, Severity.LOW, 3.0, "Token is not a well-formed JWT",
                        "S1", "Token could not be decoded into header.payload.signature.",
                        "Use a valid JWT; confirm the application actually uses JWTs.", false);
            }
            Jwt jwt = parsed.get();
            String evidence = "alg=" + jwt.alg() + " typ=" + jwt.typ() + " kid=" + jwt.kid()
                    + (jwt.exp() == null ? "" : " exp=" + jwt.exp())
                    + (jwt.nbf() == null ? "" : " nbf=" + jwt.nbf());
            if ("none".equalsIgnoreCase(jwt.alg()) || jwt.alg() == null) {
                return new Finding("S1", ID, Severity.MEDIUM, 6.0, "Weak or missing algorithm declaration",
                        "S1", evidence, "Restrict accepted algorithms to an explicit allowlist.", false);
            }
            StringBuilder sb = new StringBuilder(evidence);
            if (jwt.exp() == null) {
                sb.append("; missing exp claim");
            }
            return new Finding("S1", ID, Severity.LOW, 2.5, "JWT structural snapshot", "S1",
                    sb.toString(), "Verify expiry/nbf policy meets the application security requirements.", false);
        }
    }

    private static final class AlgNoneStep implements TestStep {
        @Override
        public String id() {
            return "S2";
        }

        @Override
        public String description() {
            return "Inject alg=none with empty signature";
        }

        @Override
        public boolean destructive() {
            return true;
        }

        @Override
        public Finding run(TestCaseContext ctx) throws Exception {
            ctx.sandbox.authorize("S2", true);
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null) {
                return null;
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return null;
            }
            Jwt jwt = parsed.get();
            String forged = JwtTools.buildUnsigned(
                    JwtTools.json(JwtTools.header("none", "JWT", jwt.kid())), jwt.payloadJson());
            FacadeRequest mutated = request.withHeader("Authorization", "Bearer " + forged);
            return acceptance(ctx, mutated, send(ctx, mutated), "S2",
                    "Token accepted with alg:none");
        }
    }

    private static final class Rs256Hs256Step implements TestStep {
        @Override
        public String id() {
            return "S3";
        }

        @Override
        public String description() {
            return "Attempt RS256 to HS256 algorithm confusion with an HMAC secret";
        }

        @Override
        public boolean destructive() {
            return true;
        }

        @Override
        public Finding run(TestCaseContext ctx) throws Exception {
            ctx.sandbox.authorize("S3", true);
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null || ctx.tokenPool.isEmpty()) {
                return null;
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return null;
            }
            Jwt jwt = parsed.get();
            String secret = ctx.tokenPool.get(0);
            String forged = JwtTools.sign(JwtTools.json(JwtTools.header("HS256", "JWT", jwt.kid())),
                    jwt.payloadJson(), secret);
            FacadeRequest mutated = request.withHeader("Authorization", "Bearer " + forged);
            return acceptance(ctx, mutated, send(ctx, mutated), "S3",
                    "Token accepted via HS256 (key confusion candidate)");
        }
    }

    private static final class SignatureStripStep implements TestStep {
        @Override
        public String id() {
            return "S4";
        }

        @Override
        public String description() {
            return "Truncate and strip the token signature";
        }

        @Override
        public boolean destructive() {
            return true;
        }

        @Override
        public Finding run(TestCaseContext ctx) throws Exception {
            ctx.sandbox.authorize("S4", true);
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null) {
                return null;
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return null;
            }
            Jwt jwt = parsed.get();
            String headerPart = JwtInspector.encode(jwt.headerJson());
            String payloadPart = JwtInspector.encode(jwt.payloadJson());
            String truncated = headerPart + "." + payloadPart + jwt.signature().substring(0,
                    Math.max(1, jwt.signature().length() / 2));
            FacadeRequest mutated = request.withHeader("Authorization", "Bearer " + truncated);
            return acceptance(ctx, mutated, send(ctx, mutated), "S4",
                    "Token with truncated signature accepted");
        }
    }

    private static final class KidPathTraversalStep implements TestStep {
        @Override
        public String id() {
            return "S5";
        }

        @Override
        public String description() {
            return "Inject path-traversal style kid values";
        }

        @Override
        public boolean destructive() {
            return true;
        }

        @Override
        public Finding run(TestCaseContext ctx) throws Exception {
            ctx.sandbox.authorize("S5", true);
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null) {
                return null;
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return null;
            }
            Jwt jwt = parsed.get();
            for (String kid : List.of("../../dev/null", "/etc/passwd", "../../../etc/shadow")) {
                String forged = JwtTools.sign(JwtTools.kidPayload(kid), jwt.payloadJson(),
                        ctx.tokenPool.isEmpty() ? "dummy" : ctx.tokenPool.get(0));
                FacadeRequest mutated = request.withHeader("Authorization", "Bearer " + forged);
                FacadeResponse response = send(ctx, mutated);
                boolean accepted = JwtTools.indicatesAcceptance(response.status(), response.bodyText());
                if (accepted) {
                    return new Finding("S5", ID, Severity.MEDIUM, 6.5,
                            "kid value traversal produced an accepted token", "S5",
                            "kid=" + kid + " status=" + response.status(),
                            "Validate kid against an allowlist of known keys; never use it as a filesystem path.", true);
                }
            }
            return null;
        }
    }

    private static final class ExpiryBoundaryStep implements TestStep {
        @Override
        public String id() {
            return "S6";
        }

        @Override
        public String description() {
            return "Inspect expiry/not-before claim handling";
        }

        @Override
        public boolean destructive() {
            return false;
        }

        @Override
        public Finding run(TestCaseContext ctx) {
            FacadeRequest request = ctx.profileTargetRequest();
            String token = bearerToken(request);
            if (token == null) {
                return null;
            }
            Optional<Jwt> parsed = JwtInspector.parse(token);
            if (parsed.isEmpty()) {
                return null;
            }
            Jwt jwt = parsed.get();
            List<String> issues = new ArrayList<>();
            if (jwt.exp() != null && jwt.exp() < System.currentTimeMillis() / 1000) {
                issues.add("exp is in the past yet still in use");
            }
            if (jwt.exp() == null) {
                issues.add("no exp claim");
            }
            if (jwt.nbf() != null && jwt.nbf() > System.currentTimeMillis() / 1000) {
                issues.add("issued before nbf");
            }
            if (issues.isEmpty()) {
                return null;
            }
            return new Finding("S6", ID, Severity.MEDIUM, 5.0, "Token life-cycle concerns", "S6",
                    String.join("; ", issues),
                    "Enforce exp/nbf/iat windows and reject stale tokens server side.", false);
        }
    }

    private static final class ReplaySwapStep implements TestStep {
        @Override
        public String id() {
            return "S7";
        }

        @Override
        public String description() {
            return "Detect cross-user token replay (manual review advisory)";
        }

        @Override
        public boolean destructive() {
            return false;
        }

        @Override
        public Finding run(TestCaseContext ctx) {
            if (ctx.tokenPool.size() < 2) {
                return null;
            }
            return new Finding("S7", ID, Severity.LOW, 3.5, "Token replay advisory",
                    "S7",
                    "Two distinct tokens supplied. Manually verify that a token issued to one "
                            + "principal cannot access another principal's resources.",
                    "Bind tokens to principals and enforce per-resource authorization.", false);
        }
    }
}