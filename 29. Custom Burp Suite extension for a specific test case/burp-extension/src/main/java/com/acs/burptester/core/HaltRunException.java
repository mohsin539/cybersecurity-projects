package com.acs.burptester.core;

public final class HaltRunException extends RuntimeException {

    public HaltRunException(String message) {
        super(message);
    }
}