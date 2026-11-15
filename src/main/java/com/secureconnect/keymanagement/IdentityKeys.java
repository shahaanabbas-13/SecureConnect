package com.secureconnect.keymanagement;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/** Local Ed25519 identity keys used to authenticate ephemeral X25519 key shares. */
public final class IdentityKeys {
    private static final Path KEY_DIRECTORY = Path.of("keys");

    private IdentityKeys() {
    }

    public static String generate(String username) throws IOException {
        validateUsername(username);
        Files.createDirectories(KEY_DIRECTORY);
        Path privateFile = privatePath(username);
        Path publicFile = publicPath(username);
        if (Files.exists(privateFile) || Files.exists(publicFile)) {
            throw new IOException("key files already exist for " + username + "; move them aside before regenerating");
        }

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            KeyPair pair = generator.generateKeyPair();
            Files.writeString(privateFile, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.writeString(publicFile, Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        } catch (GeneralSecurityException exception) {
            deleteIfExists(privateFile);
            deleteIfExists(publicFile);
            throw new IOException("Ed25519 is unavailable in this Java runtime", exception);
        } catch (IOException exception) {
            deleteIfExists(privateFile);
            deleteIfExists(publicFile);
            throw exception;
        }
    }

    public static PrivateKey loadPrivate(String username) throws IOException {
        validateUsername(username);
        String encoded = Files.readString(privatePath(username)).trim();
        try {
            byte[] bytes = Base64.getDecoder().decode(encoded);
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IOException("could not load Ed25519 identity key for " + username, exception);
        }
    }

    public static PublicKey decodePinnedPublicKey(String encoded) {
        try {
            byte[] bytes = Base64.getDecoder().decode(encoded.trim());
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalArgumentException("trusted peer key must be a Base64 Ed25519 public key", exception);
        }
    }

    public static String fingerprint(String encodedPublicKey) {
        try {
            byte[] publicKey = Base64.getDecoder().decode(encodedPublicKey.trim());
            return HexFormat.ofDelimiter(":").withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalArgumentException("could not calculate public key fingerprint", exception);
        }
    }

    public static Path privatePath(String username) {
        return KEY_DIRECTORY.resolve(username + ".ed25519.private");
    }

    public static Path publicPath(String username) {
        return KEY_DIRECTORY.resolve(username + ".ed25519.public");
    }

    private static void validateUsername(String username) {
        if (username == null || !username.matches("[A-Za-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("username must use 1-32 letters, digits, underscores, or hyphens");
        }
    }

    private static void deleteIfExists(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Preserve the original key generation error.
        }
    }
}
