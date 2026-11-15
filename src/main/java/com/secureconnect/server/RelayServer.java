package com.secureconnect.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Local-only ciphertext relay for the educational messaging prototype. */
public final class RelayServer {
    private final int port;
    private final Map<String, ClientConnection> clients = new ConcurrentHashMap<>();
    private final Map<String, String> keyAnnouncements = new ConcurrentHashMap<>();
    private final ExecutorService clientWorkers = Executors.newCachedThreadPool();

    public RelayServer(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        this.port = port;
    }

    public void start() throws IOException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket serverSocket = new ServerSocket(port, 50, loopback)) {
            System.out.println("SecureConnect relay listening on " + loopback.getHostAddress()
                    + ":" + port);
            System.out.println("Plaintext prototype — do not expose this relay to a network.");
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();
                clientWorkers.execute(() -> handleClient(socket));
            }
        } finally {
            clientWorkers.shutdownNow();
        }
    }

    private void handleClient(Socket socket) {
        ClientConnection connection = null;
        try {
            connection = new ClientConnection(socket);
            String joinRequest = connection.input.readLine();
            String username = parseJoin(joinRequest);
            connection.username = username;

            ClientConnection existing = clients.putIfAbsent(username, connection);
            if (existing != null) {
                connection.send("ERROR\tThat username is already connected.");
                return;
            }

            connection.send("WELCOME\t" + username);
            System.out.println(username + " connected from localhost.");
            for (Map.Entry<String, String> announcement : keyAnnouncements.entrySet()) {
                if (!announcement.getKey().equals(username)) {
                    connection.send(announcement.getValue());
                }
            }

            String line;
            while ((line = connection.input.readLine()) != null) {
                if ("QUIT".equals(line)) {
                    break;
                }
                if (line.startsWith("KEY\t")) {
                    handleKeyAnnouncement(connection, line);
                } else {
                    handleMessage(connection, line);
                }
            }
        } catch (IOException | IllegalArgumentException exception) {
            if (connection != null && connection.username != null) {
                System.out.println("Connection for " + connection.username
                        + " ended: " + exception.getMessage());
            }
        } finally {
            if (connection != null) {
                if (connection.username != null) {
                    boolean wasRegistered = clients.remove(connection.username, connection);
                    if (wasRegistered) {
                        keyAnnouncements.remove(connection.username);
                        broadcast("PEERLEFT\t" + connection.username, connection);
                        System.out.println(connection.username + " disconnected.");
                    }
                }
                connection.close();
            } else {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // The peer may already have closed the socket.
                }
            }
        }
    }

    private void handleKeyAnnouncement(ClientConnection sender, String line) throws IOException {
        String[] fields = line.split("\\t", 4);
        if (fields.length != 4) {
            sender.send("ERROR\tMalformed key announcement.");
            return;
        }
        String forwarded = "PEERKEY\t" + sender.username + "\t" + fields[1]
                + "\t" + fields[2] + "\t" + fields[3];
        keyAnnouncements.put(sender.username, forwarded);
        broadcast(forwarded, sender);
    }

    private void broadcast(String message, ClientConnection excluded) {
        for (ClientConnection client : clients.values()) {
            if (client != excluded) {
                try {
                    client.send(message);
                } catch (IOException ignored) {
                    // The recipient's handler will remove a disconnected client.
                }
            }
        }
    }

    private void handleMessage(ClientConnection sender, String line) throws IOException {
        String[] fields = line.split("\\t", 5);
        if (fields.length != 5 || !"SEND".equals(fields[0])) {
            sender.send("ERROR\tExpected SEND, recipient, sequence, key version, and envelope.");
            return;
        }

        String recipientName = fields[1];
        if (!isValidUsername(recipientName)) {
            sender.send("ERROR\tRecipient name is invalid.");
            return;
        }

        final long sequence;
        final long keyVersion;
        try {
            sequence = Long.parseLong(fields[2]);
            keyVersion = Long.parseLong(fields[3]);
            if (sequence < 1 || keyVersion < 0) {
                throw new NumberFormatException("negative message position");
            }
        } catch (NumberFormatException exception) {
            sender.send("ERROR\tMessage sequence or key version was invalid.");
            return;
        }

        final String envelope;
        try {
            envelope = new String(Base64.getDecoder().decode(fields[4]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            sender.send("ERROR\tMessage envelope encoding was invalid.");
            return;
        }
        if (envelope.isBlank()) {
            sender.send("ERROR\tMessage envelope cannot be empty.");
            return;
        }

        ClientConnection recipient = clients.get(recipientName);
        if (recipient == null) {
            sender.send("ERROR\t" + recipientName + " is not connected.");
            return;
        }

        String encodedEnvelope = Base64.getEncoder().encodeToString(
                envelope.getBytes(StandardCharsets.UTF_8));
        try {
            recipient.send("DELIVER\t" + sender.username + "\t" + sequence + "\t"
                    + keyVersion + "\t" + encodedEnvelope);
            sender.send("SENT\t" + recipientName);
        } catch (IOException exception) {
            sender.send("ERROR\tCould not deliver message to " + recipientName + ".");
        }
    }

    private static String parseJoin(String line) throws IOException {
        if (line == null) {
            throw new IOException("client closed before joining");
        }
        String[] fields = line.split("\\t", 2);
        if (fields.length != 2 || !"JOIN".equals(fields[0]) || !isValidUsername(fields[1])) {
            throw new IOException("invalid JOIN request");
        }
        return fields[1];
    }

    private static boolean isValidUsername(String username) {
        return username != null && username.matches("[A-Za-z0-9_-]{1,32}");
    }

    private static final class ClientConnection {
        private final Socket socket;
        private final BufferedReader input;
        private final BufferedWriter output;
        private String username;

        private ClientConnection(Socket socket) throws IOException {
            this.socket = socket;
            this.input = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8));
            this.output = new BufferedWriter(new OutputStreamWriter(
                    socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        private synchronized void send(String line) throws IOException {
            output.write(line);
            output.newLine();
            output.flush();
        }

        private void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // The peer may already have closed the socket.
            }
        }
    }
}
