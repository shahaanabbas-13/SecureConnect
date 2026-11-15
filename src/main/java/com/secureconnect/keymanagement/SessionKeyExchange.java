package com.secureconnect.keymanagement;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Signed ephemeral X25519 exchange followed by HKDF-SHA-256 session-key derivation. */
public final class SessionKeyExchange {
    private static final String VERSION = "SC-Key-v1";
    private static final int SESSION_ID_BYTES = 16;

    private SessionKeyExchange() {
    }

    public static LocalSession start(String username, PrivateKey identityPrivateKey) {
        try {
            KeyPair ephemeral = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            byte[] sessionId = new byte[SESSION_ID_BYTES];
            new SecureRandom().nextBytes(sessionId);
            String sessionId64 = Base64.getEncoder().encodeToString(sessionId);
            String ephemeralPublic64 = Base64.getEncoder().encodeToString(ephemeral.getPublic().getEncoded());

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(identityPrivateKey);
            signer.update(canonical(username, sessionId64, ephemeralPublic64));
            String signature64 = Base64.getEncoder().encodeToString(signer.sign());
            return new LocalSession(ephemeral.getPrivate(), sessionId, sessionId64,
                    ephemeralPublic64, signature64);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("X25519/Ed25519 is unavailable in this Java runtime", exception);
        }
    }

    public static byte[] deriveSessionKey(String localUsername, String peerUsername,
                                          LocalSession local, String peerSessionId64,
                                          String peerEphemeralPublic64, String peerSignature64,
                                          PublicKey trustedPeerSigningKey) {
        if (localUsername.equals(peerUsername)) {
            throw new IllegalArgumentException("cannot establish a session with the same username");
        }

        try {
            byte[] peerSessionId = Base64.getDecoder().decode(peerSessionId64);
            if (peerSessionId.length != SESSION_ID_BYTES) {
                throw new IllegalArgumentException("peer session identifier has an invalid length");
            }
            byte[] signatureBytes = Base64.getDecoder().decode(peerSignature64);
            PublicKey peerEphemeral = KeyFactory.getInstance("X25519").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(peerEphemeralPublic64)));

            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(trustedPeerSigningKey);
            verifier.update(canonical(peerUsername, peerSessionId64, peerEphemeralPublic64));
            if (!verifier.verify(signatureBytes)) {
                throw new SecurityException("peer key signature did not match the pinned identity key");
            }

            KeyAgreement agreement = KeyAgreement.getInstance("X25519");
            agreement.init(local.ephemeralPrivateKey);
            agreement.doPhase(peerEphemeral, true);
            byte[] sharedSecret = agreement.generateSecret();
            int nonzero = 0;
            for (byte value : sharedSecret) {
                nonzero |= value;
            }
            if (nonzero == 0) {
                throw new SecurityException("peer supplied an invalid X25519 public key");
            }

            byte[] salt = localUsername.compareTo(peerUsername) < 0
                    ? concatenate(local.sessionId, peerSessionId)
                    : concatenate(peerSessionId, local.sessionId);
            String first = localUsername.compareTo(peerUsername) < 0 ? localUsername : peerUsername;
            String second = localUsername.compareTo(peerUsername) < 0 ? peerUsername : localUsername;
            byte[] info = ("SecureConnect session v1\u0000" + first + "\u0000" + second)
                    .getBytes(StandardCharsets.UTF_8);
            byte[] derived = hkdfSha256(sharedSecret, salt, info, 32);
            java.util.Arrays.fill(sharedSecret, (byte) 0);
            return derived;
        } catch (SecurityException | IllegalArgumentException exception) {
            throw exception;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("could not establish an authenticated session key", exception);
        }
    }

    private static byte[] canonical(String username, String sessionId64, String ephemeralPublic64) {
        return (VERSION + "\n" + username + "\n" + sessionId64 + "\n" + ephemeralPublic64)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] pseudorandomKey = mac.doFinal(inputKeyMaterial);
        byte[] output = new byte[length];
        byte[] previousBlock = new byte[0];
        int offset = 0;
        int counter = 1;
        while (offset < length) {
            mac.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
            mac.update(previousBlock);
            mac.update(info);
            mac.update((byte) counter++);
            previousBlock = mac.doFinal();
            int copyLength = Math.min(previousBlock.length, length - offset);
            System.arraycopy(previousBlock, 0, output, offset, copyLength);
            offset += copyLength;
        }
        java.util.Arrays.fill(pseudorandomKey, (byte) 0);
        java.util.Arrays.fill(previousBlock, (byte) 0);
        return output;
    }

    private static byte[] concatenate(byte[] first, byte[] second) {
        return ByteBuffer.allocate(first.length + second.length).put(first).put(second).array();
    }

    public record LocalSession(PrivateKey ephemeralPrivateKey, byte[] sessionId,
                               String sessionIdBase64, String ephemeralPublicBase64,
                               String signatureBase64) {
        public String announcement() {
            return "KEY\t" + sessionIdBase64 + "\t" + ephemeralPublicBase64 + "\t" + signatureBase64;
        }
    }
}
