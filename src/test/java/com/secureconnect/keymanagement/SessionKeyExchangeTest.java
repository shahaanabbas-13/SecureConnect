package com.secureconnect.keymanagement;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SessionKeyExchangeTest {
    @Test
    void signedX25519ExchangesDeriveTheSameSessionRoot() throws Exception {
        KeyPair aliceIdentity = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair bobIdentity = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        SessionKeyExchange.LocalSession alice = SessionKeyExchange.start("Alice", aliceIdentity.getPrivate());
        SessionKeyExchange.LocalSession bob = SessionKeyExchange.start("Bob", bobIdentity.getPrivate());

        byte[] aliceRoot = SessionKeyExchange.deriveSessionKey("Alice", "Bob", alice,
                bob.sessionIdBase64(), bob.ephemeralPublicBase64(), bob.signatureBase64(), bobIdentity.getPublic());
        byte[] bobRoot = SessionKeyExchange.deriveSessionKey("Bob", "Alice", bob,
                alice.sessionIdBase64(), alice.ephemeralPublicBase64(), alice.signatureBase64(), aliceIdentity.getPublic());
        try {
            assertArrayEquals(aliceRoot, bobRoot);
            assertNotEquals(alice.sessionIdBase64(), bob.sessionIdBase64());

            byte[] changedSignature = Base64.getDecoder().decode(bob.signatureBase64());
            changedSignature[0] ^= 1;
            String tamperedSignature = Base64.getEncoder().encodeToString(changedSignature);
            assertThrows(SecurityException.class, () -> SessionKeyExchange.deriveSessionKey("Alice", "Bob", alice,
                    bob.sessionIdBase64(), bob.ephemeralPublicBase64(), tamperedSignature, bobIdentity.getPublic()));
        } finally {
            java.util.Arrays.fill(aliceRoot, (byte) 0);
            java.util.Arrays.fill(bobRoot, (byte) 0);
        }
    }
}
