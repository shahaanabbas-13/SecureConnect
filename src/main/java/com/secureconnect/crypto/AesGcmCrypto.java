package com.secureconnect.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/** AES-256-GCM message protection for the local educational prototype. */
public final class AesGcmCrypto {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String VERSION_PREFIX = "SC1.";
    private static final int KEY_LENGTH_BYTES = 32;
    private static final int NONCE_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private final SecretKeySpec key;
    private final SecureRandom secureRandom = new SecureRandom();

    public AesGcmCrypto(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
        this.key = new SecretKeySpec(keyBytes.clone(), "AES");
    }

    /** Encrypts plaintext and authenticates the supplied routing context. */
    public String encrypt(String plaintext, String sender, String recipient,
                          long sequence, long keyVersion) {
        validateMessagePosition(sequence, keyVersion);
        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(context(sender, recipient, sequence, keyVersion));
            byte[] ciphertextAndTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] envelope = ByteBuffer.allocate(nonce.length + ciphertextAndTag.length)
                    .put(nonce)
                    .put(ciphertextAndTag)
                    .array();
            return VERSION_PREFIX + Base64.getEncoder().encodeToString(envelope);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("AES-GCM encryption failed", exception);
        }
    }

    /** Verifies the GCM tag before returning plaintext. */
    public String decrypt(String encodedEnvelope, String sender, String recipient,
                          long sequence, long keyVersion) {
        validateMessagePosition(sequence, keyVersion);
        if (encodedEnvelope == null || !encodedEnvelope.startsWith(VERSION_PREFIX)) {
            throw new IllegalArgumentException("Unsupported or malformed encrypted message");
        }

        final byte[] envelope;
        try {
            envelope = Base64.getDecoder().decode(encodedEnvelope.substring(VERSION_PREFIX.length()));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Malformed encrypted message encoding", exception);
        }
        if (envelope.length < NONCE_LENGTH_BYTES + TAG_LENGTH_BITS / 8) {
            throw new IllegalArgumentException("Encrypted message is too short");
        }

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        byte[] ciphertextAndTag = new byte[envelope.length - NONCE_LENGTH_BYTES];
        System.arraycopy(envelope, 0, nonce, 0, nonce.length);
        System.arraycopy(envelope, nonce.length, ciphertextAndTag, 0, ciphertextAndTag.length);

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(context(sender, recipient, sequence, keyVersion));
            return new String(cipher.doFinal(ciphertextAndTag), StandardCharsets.UTF_8);
        } catch (AEADBadTagException exception) {
            throw new SecurityException("Message authentication failed; message rejected", exception);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("AES-GCM decryption failed", exception);
        }
    }

    private static byte[] context(String sender, String recipient, long sequence, long keyVersion) {
        return ("SecureConnect-message-v2\u0000" + sender + "\u0000" + recipient
                + "\u0000" + sequence + "\u0000" + keyVersion)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static void validateMessagePosition(long sequence, long keyVersion) {
        if (sequence < 1 || keyVersion < 0) {
            throw new IllegalArgumentException("sequence must be positive and key version nonnegative");
        }
    }
}
