package com.secureconnect.crypto;

import com.secureconnect.keymanagement.SessionKeyExchange;

import java.util.Arrays;

/** Derives a new AES-GCM key for each fixed-size message epoch. */
public final class MessageKeySchedule {
    public static final long MESSAGES_PER_KEY_VERSION = 10;

    private final String username;
    private final String peerUsername;
    private final byte[] sessionRootKey;

    public MessageKeySchedule(byte[] sessionRootKey, String username, String peerUsername) {
        if (sessionRootKey == null || sessionRootKey.length != 32) {
            throw new IllegalArgumentException("session root key must be 32 bytes");
        }
        this.sessionRootKey = sessionRootKey.clone();
        this.username = username;
        this.peerUsername = peerUsername;
    }

    public long keyVersionFor(long sequence) {
        if (sequence < 1) {
            throw new IllegalArgumentException("message sequence must be positive");
        }
        return (sequence - 1) / MESSAGES_PER_KEY_VERSION;
    }

    public String encrypt(String plaintext, long sequence) {
        long version = keyVersionFor(sequence);
        byte[] messageKey = derive(version);
        try {
            return new AesGcmCrypto(messageKey).encrypt(plaintext, username, peerUsername,
                    sequence, version);
        } finally {
            Arrays.fill(messageKey, (byte) 0);
        }
    }

    public String decrypt(String envelope, String sender, long sequence, long version) {
        long expectedVersion = keyVersionFor(sequence);
        if (version != expectedVersion) {
            throw new SecurityException("message key version did not match its sequence");
        }
        byte[] messageKey = derive(version);
        try {
            return new AesGcmCrypto(messageKey).decrypt(envelope, sender, username,
                    sequence, version);
        } finally {
            Arrays.fill(messageKey, (byte) 0);
        }
    }

    public void clear() {
        Arrays.fill(sessionRootKey, (byte) 0);
    }

    private byte[] derive(long version) {
        return SessionKeyExchange.deriveMessageKey(sessionRootKey, username, peerUsername, version);
    }
}
