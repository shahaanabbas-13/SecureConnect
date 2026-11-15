package com.secureconnect.client;

import com.secureconnect.crypto.AesGcmCrypto;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Console chat client for the local plaintext messaging milestone. */
public final class ChatClient {
    private final String host;
    private final int port;
    private final String username;
    private final AesGcmCrypto crypto;

    public ChatClient(String host, int port, String username, byte[] demoKey) {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("host cannot be empty");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        if (username == null || !username.matches("[A-Za-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("username must use 1-32 letters, digits, underscores, or hyphens");
        }
        this.host = host;
        this.port = port;
        this.username = username;
        this.crypto = new AesGcmCrypto(demoKey);
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

            System.out.println("Connected to relay as " + username + " (AES-256-GCM enabled).");
            System.out.println("The shared demo key is manually provisioned; this is not secure key exchange.");
            System.out.println("Send with: /to <username> <message>    Exit with: /quit");

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
        if (!input.startsWith("/to ")) {
            System.out.println("Use /to <username> <message> or /quit.");
            return;
        }
        int recipientEnd = input.indexOf(' ', 4);
        if (recipientEnd < 0 || recipientEnd == input.length() - 1) {
            System.out.println("Usage: /to <username> <message>");
            return;
        }
        String recipient = input.substring(4, recipientEnd);
        String message = input.substring(recipientEnd + 1);
        if (!recipient.matches("[A-Za-z0-9_-]{1,32}")) {
            System.out.println("Recipient must use 1-32 letters, digits, underscores, or hyphens.");
            return;
        }

        String encryptedMessage = crypto.encrypt(message, username, recipient);
        String encodedEnvelope = Base64.getEncoder().encodeToString(
                encryptedMessage.getBytes(StandardCharsets.UTF_8));
        serverOutput.write("SEND\t" + recipient + "\t" + encodedEnvelope);
        serverOutput.newLine();
        serverOutput.flush();
    }

    private void receiveMessages(BufferedReader serverInput) {
        try {
            String line;
            while ((line = serverInput.readLine()) != null) {
                String[] fields = line.split("\\t", 3);
                switch (fields[0]) {
                    case "DELIVER" -> {
                        if (fields.length == 3) {
                            try {
                                String encryptedMessage = new String(Base64.getDecoder().decode(fields[2]),
                                        StandardCharsets.UTF_8);
                                String message = crypto.decrypt(encryptedMessage, fields[1], username);
                                System.out.println("\n[" + fields[1] + "]: " + message);
                                System.out.print("> ");
                            } catch (IllegalArgumentException | SecurityException exception) {
                                System.out.println("\n[SECURITY] Message rejected: " + exception.getMessage());
                                System.out.print("> ");
                            }
                        }
                    }
                    case "SENT" -> {
                        if (fields.length == 2) {
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
}
