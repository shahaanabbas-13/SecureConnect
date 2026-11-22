package com.secureconnect.security;

/** Tracks the next permitted inbound message sequence for one authenticated session. */
public final class IncomingSequenceGuard {
    private long expectedSequence = 1;

    /** Returns true and advances only when the supplied sequence is exactly the next one expected. */
    public synchronized boolean accept(long sequence) {
        if (sequence != expectedSequence || expectedSequence == Long.MAX_VALUE) {
            return false;
        }
        expectedSequence++;
        return true;
    }

    public synchronized long expectedSequence() {
        return expectedSequence;
    }
}
