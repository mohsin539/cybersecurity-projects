package com.acs.burptester.core;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public final class SafeExecutionSandbox {

    private final boolean dryRun;
    private final int maxRequests;
    private final long interRequestDelayMillis;
    private final Lock lock = new ReentrantLock();
    private int dispatched;

    public SafeExecutionSandbox(boolean dryRun, int maxRequests, long interRequestDelayMillis) {
        this.dryRun = dryRun;
        this.maxRequests = Math.max(1, maxRequests);
        this.interRequestDelayMillis = Math.max(0, interRequestDelayMillis);
    }

    public void authorize(String stepId, boolean destructive) {
        lock.lock();
        try {
            if (destructive && dryRun) {
                throw new HaltRunException("dry-run: destructive step " + stepId + " blocked by policy");
            }
            if (dispatched >= maxRequests) {
                throw new HaltRunException("request budget exhausted after " + dispatched + " requests");
            }
            dispatched++;
            if (interRequestDelayMillis > 0) {
                try {
                    Thread.sleep(interRequestDelayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } finally {
            lock.unlock();
        }
    }

    public int dispatched() {
        lock.lock();
        try {
            return dispatched;
        } finally {
            lock.unlock();
        }
    }
}