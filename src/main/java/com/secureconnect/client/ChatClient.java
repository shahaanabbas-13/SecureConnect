package com.secureconnect.client;

import com.secureconnect.crypto.MessageKeySchedule;
import com.secureconnect.keymanagement.SessionKeyExchange;
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
import java.util.concurrent.atomic.AtomicLong;

/** Console chat client with signed ephemeral X25519 key establishment. */
public final class ChatClient {
    private final String host;
    private final int port;
    private final String username;
    private final String peerUsername;
    private final SSLContext tlsContext;
    private final ClientConsole console;
    private final PublicKey trustedPeerSigningKey;
    private final SessionKeyExchange.LocalSession localSession;
    private volatile MessageKeySchedule keySchedule;
    private final AtomicLong nextOutgoingSequence = new AtomicLong(1);
    private long nextIncomingSequence = 1;
    private long lastAnnouncedOutgoingVersion = -1;

    public ChatClient(String host, int port, String username, String peerUsername,
                      PrivateKey identityPrivateKey, PublicKey trustedPeerSigningKey,
                      SSLContext tlsContext, ClientConsole console) {
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
        this.localSession = SessionKeyExchange.start(username, identityPrivateKey);
    }

    public void run() throws IOException {
        String action = console.readLine("Account action (register/login): ");
        if (action == null || !(action.equalsIgnoreCase("register") || action.equalsIgnoreCase("login"))) {
            System.out.println("Account action must be register or login.");
            return;
        }
        String passwordPrompt = action.equalsIgnoreCase("register")
                ? "Password (minimum 12 characters): " : "Password: ";
        char[] password = console.readPassword(passwordPrompt);
        if (password == null) {
            System.out.println("No password was provided.");
            return;
        }
        if (action.equalsIgnoreCase("register")) {
            char[] confirmation = console.readPassword("Confirm password: ");
            if (!java.util.Arrays.equals(password, confirmation)) {
                java.util.Arrays.fill(password, '\0');
                if (confirmation != null) java.util.Arrays.fill(confirmation, '\0');
                System.out.println("Passwords did not match.");
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
                System.out.println(welcome == null ? "Relay closed the TLS connection."
                        : welcome.substring("AUTH_ERROR\t".length()));
                return;
            }
            if (!welcome.equals("AUTH_OK\t" + username)) {
                throw new IOException("unexpected TLS relay authentication response");
            }

            serverOutput.write(localSession.announcement());
            serverOutput.newLine();
            serverOutput.flush();

            System.out.println("Authenticated over TLS as " + username + ".");
            System.out.println("This account session is bound to this TLS connection.");
            System.out.println("Waiting for " + peerUsername + " to establish an authenticated session.");
            System.out.println("Send with: /to " + peerUsername + " <message>    Exit with: /logout");

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
        }
        System.out.println("Disconnected.");
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
            System.out.println("Use /to " + peerUsername + " <message> or /quit.");
            return;
        }
        int recipientEnd = input.indexOf(' ', 4);
        if (recipientEnd < 0 || !peerUsername.equalsIgnoreCase(input.substring(4, recipientEnd))) {
            System.out.println("Use /to " + peerUsername + " <message> or /quit.");
            return;
        }
        String message = input.substring(recipientEnd + 1);
        if (message.isBlank()) {
            System.out.println("Message cannot be empty.");
            return;
        }
        MessageKeySchedule activeSchedule = keySchedule;
        if (activeSchedule == null) {
            System.out.println("Secure session is not ready; message was not sent.");
            return;
        }

        long sequence = nextOutgoingSequence.get();
        long keyVersion = activeSchedule.keyVersionFor(sequence);
        String encryptedMessage = activeSchedule.encrypt(message, sequence);
        String encodedEnvelope = Base64.getEncoder().encodeToString(
                encryptedMessage.getBytes(StandardCharsets.UTF_8));
        serverOutput.write("SEND\t" + peerUsername + "\t" + sequence + "\t"
                + keyVersion + "\t" + encodedEnvelope);
        serverOutput.newLine();
        serverOutput.flush();
        nextOutgoingSequence.incrementAndGet();
        if (keyVersion != lastAnnouncedOutgoingVersion) {
            lastAnnouncedOutgoingVersion = keyVersion;
            System.out.println("Message key rotated to version " + keyVersion + ".");
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
                            nextIncomingSequence = 1;
                            lastAnnouncedOutgoingVersion = -1;
                            System.out.println("\n[SECURITY] Peer disconnected; session key cleared.");
                        }
                    }
                    case "SESSION_EXPIRED" -> System.out.println("\n[SESSION] "
                            + (fields.length > 1 ? fields[1] : "Session expired."));
                    case "LOGOUT_OK" -> System.out.println("\nLogged out.");
                    case "DELIVER" -> handleDelivery(fields);
                    case "SENT" -> {
                        if (fields.length >= 2) {
                            System.out.println("Message delivered to " + fields[1] + ".");
                        }
                    }
                    case "ERROR" -> System.out.println("Relay: "
                            + (fields.length > 1 ? fields[1] : "request failed"));
                    default -> System.out.println("Relay: " + line);
                }
            }
        } catch (IOException exception) {
            System.out.println("TLS relay connection ended: " + exception.getMessage());
        }
    }

    private void handlePeerKey(String[] fields) {
        if (fields.length != 5 || !peerUsername.equals(fields[1])) {
            System.out.println("\n[SECURITY] Ignored unexpected peer key announcement.");
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
            nextIncomingSequence = 1;
            lastAnnouncedOutgoingVersion = -1;
            System.out.println("\nAuthenticated encrypted session established with " + peerUsername + ".");
        } catch (IllegalArgumentException | SecurityException exception) {
            MessageKeySchedule previous = keySchedule;
            keySchedule = null;
            if (previous != null) {
                previous.clear();
            }
            System.out.println("\n[SECURITY] Peer key rejected: " + exception.getMessage());
        }
    }

    private void handleDelivery(String[] fields) {
        if (fields.length != 5 || !peerUsername.equals(fields[1])) {
            System.out.println("\n[SECURITY] Ignored message from an unexpected peer.");
            return;
        }
        MessageKeySchedule activeSchedule = keySchedule;
        if (activeSchedule == null) {
            System.out.println("\n[SECURITY] Message rejected; no authenticated session is active.");
            return;
        }
        try {
            long sequence = Long.parseLong(fields[2]);
            long keyVersion = Long.parseLong(fields[3]);
            if (sequence != nextIncomingSequence) {
                System.out.println("\n[SECURITY] Replayed or out-of-order message rejected (expected sequence "
                        + nextIncomingSequence + ", received " + sequence + ").");
                return;
            }
            String encryptedMessage = new String(Base64.getDecoder().decode(fields[4]),
                    StandardCharsets.UTF_8);
            String message = activeSchedule.decrypt(encryptedMessage, fields[1], sequence, keyVersion);
            nextIncomingSequence++;
            System.out.println("\n[" + fields[1] + "]: " + message);
        } catch (IllegalArgumentException | SecurityException exception) {
            System.out.println("\n[SECURITY] Message rejected: " + exception.getMessage());
        }
    }
}
