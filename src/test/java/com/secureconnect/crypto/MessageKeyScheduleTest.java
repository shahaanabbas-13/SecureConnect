package com.secureconnect.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MessageKeyScheduleTest {
    @Test
    void bothParticipantsDeriveAndUseTheSameTenMessageEpochs() {
        byte[] root = new byte[32];
        java.util.Arrays.fill(root, (byte) 0x5A);
        MessageKeySchedule alice = new MessageKeySchedule(root, "Alice", "Bob");
        MessageKeySchedule bob = new MessageKeySchedule(root, "Bob", "Alice");
        try {
            assertEquals(0, alice.keyVersionFor(1));
            assertEquals(0, alice.keyVersionFor(10));
            assertEquals(1, alice.keyVersionFor(11));
            assertEquals("epoch zero", bob.decrypt(alice.encrypt("epoch zero", 1), "Alice", 1, 0));
            assertEquals("epoch one", bob.decrypt(alice.encrypt("epoch one", 11), "Alice", 11, 1));
            assertThrows(SecurityException.class,
                    () -> bob.decrypt(alice.encrypt("wrong epoch", 1), "Alice", 1, 1));
        } finally {
            alice.clear();
            bob.clear();
            java.util.Arrays.fill(root, (byte) 0);
        }
    }
}
