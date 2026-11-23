package com.secureconnect.crypto;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCryptoTest {
    private static final String SENDER = "Alice";
    private static final String RECIPIENT = "Bob";
    private static final byte[] KEY = new byte[32];

    @Test
    void encryptsAndDecryptsWithFreshNonce() {
        AesGcmCrypto crypto = new AesGcmCrypto(KEY);
        String first = crypto.encrypt("Hello Bob", SENDER, RECIPIENT, 1, 0);
        String second = crypto.encrypt("Hello Bob", SENDER, RECIPIENT, 2, 0);

        assertEquals("Hello Bob", crypto.decrypt(first, SENDER, RECIPIENT, 1, 0));
        assertEquals("Hello Bob", crypto.decrypt(second, SENDER, RECIPIENT, 2, 0));
        assertNotEquals(nonce(first), nonce(second), "each encryption must use a fresh 96-bit nonce");
        assertEquals(12, nonce(first).length);
    }

    @Test
    void rejectsTamperedCiphertextAndAuthenticationTag() {
        AesGcmCrypto crypto = new AesGcmCrypto(KEY);
        String envelope = crypto.encrypt("authenticated message", SENDER, RECIPIENT, 1, 0);

        assertThrows(SecurityException.class,
                () -> crypto.decrypt(flipEnvelopeByte(envelope, 12), SENDER, RECIPIENT, 1, 0));
        byte[] decoded = decode(envelope);
        decoded[decoded.length - 1] ^= 1;
        String changedTag = "SC1." + Base64.getEncoder().encodeToString(decoded);
        assertThrows(SecurityException.class, () -> crypto.decrypt(changedTag, SENDER, RECIPIENT, 1, 0));
    }

    @Test
    void rejectsTamperedNonceAndChangedAuthenticatedContext() {
        AesGcmCrypto crypto = new AesGcmCrypto(KEY);
        String envelope = crypto.encrypt("authenticated message", SENDER, RECIPIENT, 1, 0);
        assertThrows(SecurityException.class,
                () -> crypto.decrypt(flipEnvelopeByte(envelope, 0), SENDER, RECIPIENT, 1, 0));
        assertThrows(SecurityException.class,
                () -> crypto.decrypt(envelope, SENDER, RECIPIENT, 2, 0));
        assertThrows(SecurityException.class,
                () -> crypto.decrypt(envelope, RECIPIENT, SENDER, 1, 0));
    }

    private static byte[] nonce(String envelope) {
        return java.util.Arrays.copyOfRange(decode(envelope), 0, 12);
    }

    private static String flipEnvelopeByte(String envelope, int index) {
        byte[] decoded = decode(envelope);
        decoded[index] ^= 1;
        return "SC1." + Base64.getEncoder().encodeToString(decoded);
    }

    private static byte[] decode(String envelope) {
        return Base64.getDecoder().decode(envelope.substring("SC1.".length()));
    }
}
