package com.acs.burptester.api;

public enum Severity {
    INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4);

    public final int rank;

    Severity(int rank) {
        this.rank = rank;
    }
}