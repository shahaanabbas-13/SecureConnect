package com.secureconnect.client;

import com.secureconnect.crypto.MessageKeySchedule;
import com.secureconnect.keymanagement.SessionKeyExchange;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
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
    private final PublicKey trustedPeerSigningKey;
    private final SessionKeyExchange.LocalSession localSession;
    private volatile MessageKeySchedule keySchedule;
    private final AtomicLong nextOutgoingSequence = new AtomicLong(1);
    private long nextIncomingSequence = 1;
    private long lastAnnouncedOutgoingVersion = -1;

    public ChatClient(String host, int port, String username, String peerUsername,
                      PrivateKey identityPrivateKey, PublicKey trustedPeerSigningKey) {
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
        this.localSession = SessionKeyExchange.start(username, identityPrivateKey);
    }

    public void run() throws IOException {
        try (Socket socket = new Socket(host, port);
             BufferedReader serverInput = new BufferedReader(new InputStreamReader(
                     socket.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter serverOutput = new BufferedWriter(new OutputStreamWriter(
                     socket.getOutputStream(), StandardCharsets.UTF_8))) {
            serverOutput.write("JOIN\t" + username);
            serverOutput.newLine();
            serverOutput.flush();

            String welcome = serverInput.readLine();
            if (welcome == null || welcome.startsWith("ERROR\t")) {
                throw new IOException(welcome == null ? "relay closed the connection" : welcome.substring(6));
            }
            if (!welcome.equals("WELCOME\t" + username)) {
                throw new IOException("unexpected response from relay");
            }

            serverOutput.write(localSession.announcement());
            serverOutput.newLine();
            serverOutput.flush();

            System.out.println("Connected to local relay as " + username + ".");
            System.out.println("Waiting for " + peerUsername + " to establish an authenticated session.");
            System.out.println("Send with: /to " + peerUsername + " <message>    Exit with: /quit");

            Thread receiver = new Thread(() -> receiveMessages(serverInput), "secureconnect-receiver");
            receiver.setDaemon(true);
            receiver.start();

            try (BufferedReader console = new BufferedReader(new InputStreamReader(
                    System.in, StandardCharsets.UTF_8))) {
                String input;
                while ((input = console.readLine()) != null) {
                    if ("/quit".equalsIgnoreCase(input.trim())) {
                        serverOutput.write("QUIT");
                        serverOutput.newLine();
                        serverOutput.flush();
                        break;
                    }
                    sendMessage(serverOutput, input);
                }
            }
        }
        System.out.println("Disconnected.");
    }

    private void sendMessage(BufferedWriter serverOutput, String input) throws IOException {
        String prefix = "/to " + peerUsername + " ";
        if (!input.startsWith(prefix)) {
            System.out.println("Use /to " + peerUsername + " <message> or /quit.");
            return;
        }
        String message = input.substring(prefix.length());
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
            System.out.println("Relay connection ended: " + exception.getMessage());
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
