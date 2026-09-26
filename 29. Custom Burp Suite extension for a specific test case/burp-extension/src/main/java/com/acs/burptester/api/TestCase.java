package com.acs.burptester.api;

public interface TestCase {

    String id();

    String wstgId();

    String displayName();

    java.util.List<TestStep> steps();
}