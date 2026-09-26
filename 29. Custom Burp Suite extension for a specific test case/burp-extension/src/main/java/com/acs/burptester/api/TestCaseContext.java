package com.acs.burptester.api;

import com.acs.burptester.core.AuditLog;
import com.acs.burptester.core.SafeExecutionSandbox;

import java.util.List;
import java.util.function.Consumer;

public final class TestCaseContext {

    public final TestProfile profile;
    public final FacadeRequest target;
    public final HttpFacade http;
    public final AuditLog audit;
    public final List<String> tokenPool;
    public final Consumer<String> onProgress;
    public final SafeExecutionSandbox sandbox;

    public TestCaseContext(TestProfile profile, FacadeRequest target, HttpFacade http, AuditLog audit,
                           List<String> tokenPool, Consumer<String> onProgress, SafeExecutionSandbox sandbox) {
        this.profile = profile;
        this.target = target;
        this.http = http;
        this.audit = audit;
        this.tokenPool = List.copyOf(tokenPool);
        this.onProgress = onProgress == null ? ignore -> { } : onProgress;
        this.sandbox = sandbox;
    }

    public FacadeRequest profileTargetRequest() {
        return target;
    }
}