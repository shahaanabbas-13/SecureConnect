package com.secureconnect.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Argon2id password verifier using Bouncy Castle's maintained implementation. */
public final class Argon2idPasswordHasher {
    private static final int MEMORY_KIB = 65_536;
    private static final int ITERATIONS = 3;
    private static final int PARALLELISM = 1;
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    public String hash(char[] password) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] passwordBytes = utf8(password);
        byte[] result = new byte[HASH_LENGTH];
        try {
            generate(passwordBytes, salt, result);
            return "$argon2id$v=19$m=" + MEMORY_KIB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
                    + "$" + Base64.getEncoder().withoutPadding().encodeToString(salt)
                    + "$" + Base64.getEncoder().withoutPadding().encodeToString(result);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(result, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    public boolean verify(char[] password, String encodedVerifier) {
        byte[] passwordBytes = utf8(password);
        byte[] salt = null;
        byte[] expected = null;
        byte[] actual = null;
        try {
            String[] parts = encodedVerifier.split("\\$", -1);
            if (parts.length != 6 || !parts[1].equals("argon2id") || !parts[2].equals("v=19")
                    || !parts[3].equals("m=" + MEMORY_KIB + ",t=" + ITERATIONS + ",p=" + PARALLELISM)) {
                return false;
            }
            salt = Base64.getDecoder().decode(parts[4]);
            expected = Base64.getDecoder().decode(parts[5]);
            if (salt.length != SALT_LENGTH || expected.length != HASH_LENGTH) {
                return false;
            }
            actual = new byte[HASH_LENGTH];
            generate(passwordBytes, salt, actual);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException exception) {
            return false;
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            if (salt != null) Arrays.fill(salt, (byte) 0);
            if (expected != null) Arrays.fill(expected, (byte) 0);
            if (actual != null) Arrays.fill(actual, (byte) 0);
        }
    }

    private static void generate(byte[] password, byte[] salt, byte[] output) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(MEMORY_KIB)
                .withIterations(ITERATIONS)
                .withParallelism(PARALLELISM)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        generator.generateBytes(password, output);
    }

    private static byte[] utf8(char[] password) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        if (encoded.hasArray()) {
            Arrays.fill(encoded.array(), (byte) 0);
        }
        return bytes;
    }
}
