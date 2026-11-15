package com.secureconnect.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/** Persistent local account registry with Argon2id verifiers and login throttling. */
public final class AccountService {
    private static final int MAX_FAILED_LOGINS = 5;
    private static final long LOCKOUT_MILLIS = 60_000;
    private static final Path DEFAULT_STORE = Path.of("data", "accounts.properties");

    private final Path storePath;
    private final Properties accounts = new Properties();
    private final ConcurrentHashMap<String, FailureState> failures = new ConcurrentHashMap<>();
    private final Argon2idPasswordHasher hasher = new Argon2idPasswordHasher();
    private final String dummyVerifier;

    public AccountService() throws IOException {
        String configured = System.getenv("SECURECONNECT_ACCOUNT_STORE");
        this.storePath = configured == null || configured.isBlank()
                ? DEFAULT_STORE : Path.of(configured);
        if (Files.exists(storePath)) {
            try (InputStream input = Files.newInputStream(storePath)) {
                accounts.load(input);
            }
        }
        char[] dummyPassword = new char[32];
        Arrays.fill(dummyPassword, 'x');
        try {
            dummyVerifier = hasher.hash(dummyPassword);
        } finally {
            Arrays.fill(dummyPassword, '\0');
        }
    }

    public synchronized RegistrationResult register(String username, char[] password) throws IOException {
        try {
            if (!isValidUsername(username)) {
                return RegistrationResult.INVALID_USERNAME;
            }
            if (password == null || password.length < 12 || password.length > 128) {
                return RegistrationResult.INVALID_PASSWORD;
            }
            if (accounts.containsKey(username)) {
                return RegistrationResult.ALREADY_EXISTS;
            }
            String verifier = hasher.hash(password);
            accounts.setProperty(username, verifier);
            try {
                persist();
            } catch (IOException exception) {
                accounts.remove(username);
                throw exception;
            }
            return RegistrationResult.CREATED;
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    public synchronized LoginResult authenticate(String username, char[] password) {
        try {
            if (!isValidUsername(username) || password == null) {
                return LoginResult.REJECTED;
            }
            String rateKey = username.toLowerCase(java.util.Locale.ROOT);
            FailureState state = failures.get(rateKey);
            long now = System.currentTimeMillis();
            if (state != null && state.blockedUntilMillis > now) {
                return LoginResult.THROTTLED;
            }

            String storedVerifier = accounts.getProperty(username);
            boolean valid = hasher.verify(password, storedVerifier == null ? dummyVerifier : storedVerifier);
            if (storedVerifier != null && valid) {
                failures.remove(rateKey);
                return LoginResult.AUTHENTICATED;
            }

            failures.compute(rateKey, (ignored, current) -> {
                long currentTime = System.currentTimeMillis();
                int attempts = current == null || current.windowStartedMillis + LOCKOUT_MILLIS < currentTime
                        ? 1 : current.failedAttempts + 1;
                long windowStart = attempts == 1 ? currentTime : current.windowStartedMillis;
                long blockedUntil = attempts >= MAX_FAILED_LOGINS ? currentTime + LOCKOUT_MILLIS : 0;
                return new FailureState(windowStart, attempts, blockedUntil);
            });
            FailureState updated = failures.get(rateKey);
            return updated != null && updated.blockedUntilMillis > now
                    ? LoginResult.THROTTLED : LoginResult.REJECTED;
        } finally {
            if (password != null) Arrays.fill(password, '\0');
        }
    }

    private void persist() throws IOException {
        Path parent = storePath.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temporary = storePath.resolveSibling(storePath.getFileName() + ".tmp");
        try (OutputStream output = Files.newOutputStream(temporary,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            accounts.store(output, "SecureConnect Argon2id password verifiers; never store plaintext passwords");
        }
        try {
            Files.move(temporary, storePath, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporary, storePath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public static boolean isValidUsername(String username) {
        return username != null && username.matches("[A-Za-z0-9_-]{1,32}");
    }

    public String storePathDescription() {
        return storePath.toAbsolutePath().toString();
    }

    public enum RegistrationResult { CREATED, ALREADY_EXISTS, INVALID_USERNAME, INVALID_PASSWORD }
    public enum LoginResult { AUTHENTICATED, REJECTED, THROTTLED }

    private record FailureState(long windowStartedMillis, int failedAttempts, long blockedUntilMillis) { }
}
