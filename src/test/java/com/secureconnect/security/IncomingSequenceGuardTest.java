package com.secureconnect.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IncomingSequenceGuardTest {
    @Test
    void acceptsOnlyTheNextSequenceAndDoesNotAdvanceAfterRejection() {
        IncomingSequenceGuard guard = new IncomingSequenceGuard();
        assertEquals(1, guard.expectedSequence());
        assertTrue(guard.accept(1));
        assertFalse(guard.accept(1), "duplicate must be rejected");
        assertFalse(guard.accept(3), "out-of-order message must be rejected");
        assertEquals(2, guard.expectedSequence());
        assertTrue(guard.accept(2));
        assertEquals(3, guard.expectedSequence());
    }
}
