package com.acs.burptester.api;

public interface TestStep {

    String id();

    String description();

    boolean destructive();

    Finding run(TestCaseContext ctx) throws Exception;
}