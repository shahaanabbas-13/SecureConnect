package com.secureconnect.client;

import com.secureconnect.crypto.MessageKeySchedule;
import com.secureconnect.keymanagement.SessionKeyExchange;
import com.secureconnect.security.SecurityEventLog;
import com.secureconnect.security.SecurityEventLog.Severity;
import com.secureconnect.security.IncomingSequenceGuard;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

/** Console chat client with signed ephemeral X25519 key establishment. */
public final class ChatClient {
    public interface Listener {
        default void onAuthenticated(String username) { }
        default void onStatus(String message) { }
        default void onSessionReady(String peer) { }
        default void onSessionReady(String peer, String localSessionId, String peerSessionId) {
            onSessionReady(peer);
        }
        default void onKeyVersion(long version) { }
        default void onOutgoing(String plaintext, String envelope, long sequence, long keyVersion) { }
        default void onOutgoingMeasured(String plaintext, String envelope, long sequence, long keyVersion,
                                        long encryptionNanos) {
            onOutgoing(plaintext, envelope, sequence, keyVersion);
        }
        default void onDelivered(String peer, long sequence) { }
        default void onIncoming(String sender, String plaintext, String envelope, long sequence, long keyVersion) { }
        default void onIncomingMeasured(String sender, String plaintext, String envelope, long sequence,
                                        long keyVersion, long decryptionNanos) {
            onIncoming(sender, plaintext, envelope, sequence, keyVersion);
        }
        default void onSecurity(String message) { }
        default void onDisconnected() { }
    }

    private static final Listener NO_LISTENER = new Listener() { };
    private final String host;
    private final int port;
    private final String username;
    private final String peerUsername;
    private final SSLContext tlsContext;
    private final ClientConsole console;
    private final PublicKey trustedPeerSigningKey;
    private final Listener listener;
    private final SessionKeyExchange.LocalSession localSession;
    private volatile MessageKeySchedule keySchedule;
    private final AtomicLong nextOutgoingSequence = new AtomicLong(1);
    private final ConcurrentLinkedQueue<Long> pendingDeliveryAcks = new ConcurrentLinkedQueue<>();
    private IncomingSequenceGuard incomingSequenceGuard = new IncomingSequenceGuard();
    private long lastAnnouncedOutgoingVersion = -1;

    public ChatClient(String host, int port, String username, String peerUsername,
                      PrivateKey identityPrivateKey, PublicKey trustedPeerSigningKey,
                      SSLContext tlsContext, ClientConsole console) {
        this(host, port, username, peerUsername, identityPrivateKey, trustedPeerSigningKey,
                tlsContext, console, NO_LISTENER);
    }

    public ChatClient(String host, int port, String username, String peerUsername,
                      PrivateKey identityPrivateKey, PublicKey trustedPeerSigningKey,
                      SSLContext tlsContext, ClientConsole console, Listener listener) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("host cannot be empty");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        if (username == null || !username.matches("[A-Za-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("username must use 1-32 letters, digits, underscores, or hyphens");
        }
        if (peerUsername == null || !peerUsername.matches("[A-Za-z0-9_-]{1,32}")
                || username.equals(peerUsername)) {
            throw new IllegalArgumentException("peer username must be valid and different from this username");
        }
        this.host = host;
        this.port = port;
        this.username = username;
        this.peerUsername = peerUsername;
        this.trustedPeerSigningKey = trustedPeerSigningKey;
        this.tlsContext = tlsContext;
        this.console = console;
        this.listener = listener == null ? NO_LISTENER : listener;
        this.localSession = SessionKeyExchange.start(username, identityPrivateKey);
    }

    public void run() throws IOException {
        String action = console.readLine("Account action (register/login): ");
        if (action == null || !(action.equalsIgnoreCase("register") || action.equalsIgnoreCase("login"))) {
            console.println("Account action must be register or login.");
            return;
        }
        String passwordPrompt = action.equalsIgnoreCase("register")
                ? "Password (minimum 12 characters): " : "Password: ";
        char[] password = console.readPassword(passwordPrompt);
        if (password == null) {
            console.println("No password was provided.");
            return;
        }
        if (action.equalsIgnoreCase("register")) {
            char[] confirmation = console.readPassword("Confirm password: ");
            if (!java.util.Arrays.equals(password, confirmation)) {
                java.util.Arrays.fill(password, '\0');
                if (confirmation != null) java.util.Arrays.fill(confirmation, '\0');
                console.println("Passwords did not match.");
                return;
            }
            if (confirmation != null) java.util.Arrays.fill(confirmation, '\0');
        }
        String encodedPassword = encodePassword(password);

        SSLSocket socket = (SSLSocket) tlsContext.getSocketFactory().createSocket(host, port);
        SSLParameters sslParameters = socket.getSSLParameters();
        sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(sslParameters);
        try (socket;
             BufferedReader serverInput = new BufferedReader(new InputStreamReader(
                     socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter serverOutput = new BufferedWriter(new OutputStreamWriter(
                     socket.getOutputStream(), StandardCharsets.UTF_8))) {
            socket.startHandshake();
            serverOutput.write("AUTH\t" + action.toUpperCase(java.util.Locale.ROOT)
                    + "\t" + username + "\t" + encodedPassword);
            serverOutput.newLine();
            serverOutput.flush();

            String welcome = serverInput.readLine();
            if (welcome == null || welcome.startsWith("AUTH_ERROR\t")) {
                String message = welcome == null ? "Relay closed the TLS connection."
                        : welcome.substring("AUTH_ERROR\t".length());
                console.println(message);
                listener.onStatus(message);
                return;
            }
            if (!welcome.equals("AUTH_OK\t" + username)) {
                throw new IOException("unexpected TLS relay authentication response");
            }

            serverOutput.write(localSession.announcement());
            serverOutput.newLine();
            serverOutput.flush();

            console.println("Authenticated over TLS as " + username + ".");
            console.println("This account session is bound to this TLS connection.");
            console.println("Waiting for " + peerUsername + " to establish an authenticated session.");
            console.println("Send with: /to " + peerUsername + " <message>    Exit with: /logout");
            listener.onAuthenticated(username);
            listener.onStatus("TLS authenticated; waiting for signed peer key exchange.");

            Thread receiver = new Thread(() -> receiveMessages(serverInput), "secureconnect-receiver");
            receiver.setDaemon(true);
            receiver.start();

            String input;
            while ((input = console.readChatLine()) != null) {
                    if ("/logout".equalsIgnoreCase(input.trim()) || "/quit".equalsIgnoreCase(input.trim())) {
                        serverOutput.write("LOGOUT");
                        serverOutput.newLine();
                        serverOutput.flush();
                        break;
                    }
                    sendMessage(serverOutput, input);
            }
        } finally {
            MessageKeySchedule previous = keySchedule;
            keySchedule = null;
            if (previous != null) previous.clear();
            listener.onDisconnected();
        }
        console.println("Disconnected.");
    }

    private static String encodePassword(char[] password) {
        java.nio.ByteBuffer encoded = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(password));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        java.util.Arrays.fill(password, '\0');
        try {
            return Base64.getEncoder().encodeToString(bytes);
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
            if (encoded.hasArray()) java.util.Arrays.fill(encoded.array(), (byte) 0);
        }
    }

    private void sendMessage(BufferedWriter serverOutput, String input) throws IOException {
        if (!input.regionMatches(true, 0, "/to ", 0, 4)) {
            console.println("Use /to " + peerUsername + " <message> or /quit.");
            return;
        }
        int recipientEnd = input.indexOf(' ', 4);
        if (recipientEnd < 0 || !peerUsername.equalsIgnoreCase(input.substring(4, recipientEnd))) {
            console.println("Use /to " + peerUsername + " <message> or /quit.");
            return;
        }
        String message = input.substring(recipientEnd + 1);
        if (message.isBlank()) {
            console.println("Message cannot be empty.");
            return;
        }
        MessageKeySchedule activeSchedule = keySchedule;
        if (activeSchedule == null) {
            console.println("Secure session is not ready; message was not sent.");
            listener.onStatus("Message blocked: authenticated end-to-end session is not ready.");
            return;
        }

        long sequence = nextOutgoingSequence.get();
        long keyVersion = activeSchedule.keyVersionFor(sequence);
        long encryptionStarted = System.nanoTime();
        String encryptedMessage = activeSchedule.encrypt(message, sequence);
        long encryptionNanos = System.nanoTime() - encryptionStarted;
        console.println("[CRYPTO] AES-256-GCM encryption succeeded (sequence=" + sequence
                + ", keyEpoch=" + keyVersion + ", elapsed=" + String.format(java.util.Locale.ROOT, "%.3f", encryptionNanos / 1_000.0) + " µs).");
        String encodedEnvelope = Base64.getEncoder().encodeToString(
                encryptedMessage.getBytes(StandardCharsets.UTF_8));
        pendingDeliveryAcks.add(sequence);
        try {
            serverOutput.write("SEND\t" + peerUsername + "\t" + sequence + "\t"
                    + keyVersion + "\t" + encodedEnvelope);
            serverOutput.newLine();
            serverOutput.flush();
        } catch (IOException exception) {
            pendingDeliveryAcks.remove(sequence);
            throw exception;
        }
        nextOutgoingSequence.incrementAndGet();
        console.println("[NETWORK] Encrypted SC1 envelope sent to relay (sequence=" + sequence
                + ", encodedBytes=" + encryptedMessage.getBytes(StandardCharsets.UTF_8).length + ").");
        listener.onOutgoingMeasured(message, encryptedMessage, sequence, keyVersion, encryptionNanos);
        if (keyVersion != lastAnnouncedOutgoingVersion) {
            lastAnnouncedOutgoingVersion = keyVersion;
            console.println("Message key rotated to version " + keyVersion + ".");
            listener.onKeyVersion(keyVersion);
        }
    }

    private void receiveMessages(BufferedReader serverInput) {
        try {
            String line;
            while ((line = serverInput.readLine()) != null) {
                String[] fields = line.split("\\t", 5);
                switch (fields[0]) {
                    case "PEERKEY" -> handlePeerKey(fields);
                    case "PEERLEFT" -> {
                        if (fields.length >= 2 && peerUsername.equals(fields[1])) {
                            MessageKeySchedule previous = keySchedule;
                            keySchedule = null;
                            if (previous != null) {
                                previous.clear();
                            }
                            nextOutgoingSequence.set(1);
                            incomingSequenceGuard = new IncomingSequenceGuard();
                            lastAnnouncedOutgoingVersion = -1;
                            SecurityEventLog.record("E2EE_SESSION_CLEARED", Severity.INFO, username,
                                    "Peer disconnect cleared the local end-to-end session keys.");
                            console.println("\n[SECURITY] Peer disconnected; session key cleared.");
                            listener.onSecurity("Peer disconnected; local session key cleared.");
                            listener.onStatus("Peer offline; waiting for a new authenticated key exchange.");
                        }
                    }
                    case "SESSION_EXPIRED" -> {
                        SecurityEventLog.record("SESSION_EXPIRED", Severity.WARNING, username,
                                "Relay expired this connection-bound session.");
                        console.println("\n[SESSION] "
                                + (fields.length > 1 ? fields[1] : "Session expired."));
                        listener.onSecurity("Account session expired.");
                    }
                    case "LOGOUT_OK" -> console.println("\nLogged out.");
                    case "DELIVER" -> handleDelivery(fields);
                    case "SENT" -> {
                        if (fields.length >= 2) {
                            console.println("Message delivered to " + fields[1] + ".");
                            Long acknowledgedSequence = pendingDeliveryAcks.poll();
                            listener.onDelivered(fields[1], acknowledgedSequence == null ? 0 : acknowledgedSequence);
                        }
                    }
                    case "ERROR" -> console.println("Relay: "
                            + (fields.length > 1 ? fields[1] : "request failed"));
                    default -> console.println("Relay: " + line);
                }
            }
        } catch (IOException exception) {
            console.println("TLS relay connection ended: " + exception.getMessage());
            listener.onDisconnected();
        }
    }

    private void handlePeerKey(String[] fields) {
        if (fields.length != 5 || !peerUsername.equals(fields[1])) {
            console.println("\n[SECURITY] Ignored unexpected peer key announcement.");
            listener.onSecurity("Unexpected peer key announcement ignored.");
            return;
        }
        try {
            byte[] sessionKey = SessionKeyExchange.deriveSessionKey(
                    username, peerUsername, localSession, fields[2], fields[3], fields[4],
                    trustedPeerSigningKey);
            MessageKeySchedule previous = keySchedule;
            if (previous != null) {
                previous.clear();
            }
            keySchedule = new MessageKeySchedule(sessionKey, username, peerUsername);
            java.util.Arrays.fill(sessionKey, (byte) 0);
            nextOutgoingSequence.set(1);
            lastAnnouncedOutgoingVersion = -1;
            console.println("\nAuthenticated encrypted session established with " + peerUsername + ".");
            listener.onSessionReady(peerUsername, localSession.sessionIdBase64(), fields[2]);
            listener.onStatus("End-to-end session ready: Ed25519 verified X25519 key share; HKDF session key active.");
        } catch (IllegalArgumentException | SecurityException exception) {
            MessageKeySchedule previous = keySchedule;
            keySchedule = null;
            if (previous != null) {
                previous.clear();
            }
            SecurityEventLog.record("PEER_KEY_REJECTED", Severity.ALERT, username,
                    "Peer key announcement failed pinned identity verification.");
            console.println("\n[SECURITY] Peer key rejected: " + exception.getMessage());
            listener.onSecurity("Peer key rejected: " + exception.getMessage());
            listener.onStatus("Peer key rejected; no authenticated end-to-end session is active.");
        }
    }

    private void handleDelivery(String[] fields) {
        if (fields.length != 5 || !peerUsername.equals(fields[1])) {
            console.println("\n[SECURITY] Ignored message from an unexpected peer.");
            listener.onSecurity("Message from unexpected peer ignored.");
            return;
        }
        MessageKeySchedule activeSchedule = keySchedule;
        if (activeSchedule == null) {
            console.println("\n[SECURITY] Message rejected; no authenticated session is active.");
            listener.onSecurity("Message rejected because no authenticated E2EE session is active.");
            return;
        }
        try {
            long sequence = Long.parseLong(fields[2]);
            long keyVersion = Long.parseLong(fields[3]);
            if (sequence != incomingSequenceGuard.expectedSequence()) {
                SecurityEventLog.record("REPLAY_REJECTED", Severity.ALERT, username,
                        "Rejected duplicate or out-of-order encrypted message sequence " + sequence + ".");
                console.println("\n[SECURITY] Replayed or out-of-order message rejected (expected sequence "
                        + incomingSequenceGuard.expectedSequence() + ", received " + sequence + ").");
                listener.onSecurity("Replay or sequence violation rejected: received sequence " + sequence + ".");
                return;
            }
            String encryptedMessage = new String(Base64.getDecoder().decode(fields[4]),
                    StandardCharsets.UTF_8);
            console.println("[RECEIVER] Encrypted envelope received (sequence=" + sequence
                    + ", keyEpoch=" + keyVersion + ", encodedBytes=" + encryptedMessage.getBytes(StandardCharsets.UTF_8).length + ").");
            long decryptionStarted = System.nanoTime();
            String message = activeSchedule.decrypt(encryptedMessage, fields[1], sequence, keyVersion);
            long decryptionNanos = System.nanoTime() - decryptionStarted;
            if (!incomingSequenceGuard.accept(sequence)) {
                SecurityEventLog.record("REPLAY_REJECTED", Severity.ALERT, username,
                        "Rejected duplicate or out-of-order encrypted message sequence " + sequence + ".");
                console.println("\n[SECURITY] Replayed or out-of-order message rejected.");
                listener.onSecurity("Replay or sequence violation rejected.");
                return;
            }
            console.println("[SECURITY] AES-GCM authentication tag verified; sequence " + sequence + " accepted.");
            console.println("[CRYPTO] Local decryption succeeded (elapsed="
                    + String.format(java.util.Locale.ROOT, "%.3f", decryptionNanos / 1_000.0) + " µs).");
            console.println("\n[" + fields[1] + "]: " + message);
            listener.onIncomingMeasured(fields[1], message, encryptedMessage, sequence, keyVersion,
                    decryptionNanos);
        } catch (IllegalArgumentException | SecurityException exception) {
            SecurityEventLog.record("MESSAGE_INTEGRITY_REJECTED", Severity.ALERT, username,
                    "Encrypted message envelope failed local integrity or format validation.");
            console.println("\n[SECURITY] Message rejected: " + exception.getMessage());
            listener.onSecurity("Message rejected: " + exception.getMessage());
        }
    }
}
