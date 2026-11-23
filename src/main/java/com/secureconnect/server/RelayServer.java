package com.secureconnect.server;

import com.secureconnect.security.AccountService;
import com.secureconnect.security.SecurityEventLog;
import com.secureconnect.security.SecurityEventLog.Severity;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** TLS-protected local relay with account authentication and connection-bound sessions. */
public final class RelayServer {
    private static final long MAX_SESSION_AGE_MILLIS = TimeUnit.MINUTES.toMillis(30);
    private static final long IDLE_SESSION_MILLIS = TimeUnit.MINUTES.toMillis(10);
    private final int port;
    private final SSLContext tlsContext;
    private final AccountService accounts;
    private final Map<String, ClientConnection> clients = new ConcurrentHashMap<>();
    private final Map<String, String> keyAnnouncements = new ConcurrentHashMap<>();
    private final ExecutorService clientWorkers = Executors.newCachedThreadPool();
    private final ScheduledExecutorService sessionSweeper = Executors.newSingleThreadScheduledExecutor();

    public RelayServer(int port, SSLContext tlsContext) throws IOException {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
        this.port = port;
        this.tlsContext = tlsContext;
        this.accounts = new AccountService();
    }

    public void start() throws IOException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        SSLServerSocketFactory factory = tlsContext.getServerSocketFactory();
        try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(port, 50, loopback)) {
            serverSocket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            sessionSweeper.scheduleAtFixedRate(this::expireSessions, 10, 10, TimeUnit.SECONDS);
            System.out.println("SecureConnect TLS relay listening on " + loopback.getHostAddress()
                    + ":" + port);
            System.out.println("Account store: " + accounts.storePathDescription());
            System.out.println("Sessions expire after 30 minutes total or 10 minutes idle.");
            SecurityEventLog.record("SERVER_STARTED", Severity.INFO, "relay",
                    "TLS relay started on loopback port " + port + ".");
            while (!serverSocket.isClosed()) {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                socket.setUseClientMode(false);
                clientWorkers.execute(() -> handleClient(socket));
            }
        } finally {
            sessionSweeper.shutdownNow();
            clientWorkers.shutdownNow();
        }
    }

    private void handleClient(SSLSocket socket) {
        ClientConnection connection = null;
        try {
            connection = new ClientConnection(socket);
            socket.setSoTimeout(30_000);
            socket.startHandshake();
            String authLine = connection.input.readLine();
            String username = authenticate(authLine, connection);
            if (username == null) return;

            connection.username = username;
            if (clients.putIfAbsent(username, connection) != null) {
                SecurityEventLog.record("SESSION_DUPLICATE_REJECTED", Severity.WARNING, username,
                        "A second simultaneous session was refused.");
                connection.send("AUTH_ERROR\tThis account already has an active session.");
                return;
            }
            connection.startSession();
            SecurityEventLog.record("SESSION_OPENED", Severity.INFO, username,
                    "Authenticated TLS session opened.");
            socket.setSoTimeout(0);
            connection.send("AUTH_OK\t" + username);
            System.out.println("Authenticated session opened for " + username + ".");
            for (Map.Entry<String, String> announcement : keyAnnouncements.entrySet()) {
                if (!announcement.getKey().equals(username)) {
                    connection.send(announcement.getValue());
                }
            }

            String line;
            while ((line = connection.input.readLine()) != null) {
                if (connection.isExpired(System.currentTimeMillis())) {
                    connection.send("SESSION_EXPIRED\tPlease log in again.");
                    break;
                }
                connection.touch();
                if ("LOGOUT".equals(line)) {
                    SecurityEventLog.record("SESSION_LOGOUT", Severity.INFO, username,
                            "User ended the authenticated session.");
                    connection.send("LOGOUT_OK");
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
                System.out.println("Session for " + connection.username + " ended.");
            }
        } finally {
            if (connection != null) {
                if (connection.username != null) {
                    boolean wasRegistered = clients.remove(connection.username, connection);
                    if (wasRegistered) {
                        keyAnnouncements.remove(connection.username);
                        broadcast("PEERLEFT\t" + connection.username, connection);
                        System.out.println("Authenticated session closed for " + connection.username + ".");
                        SecurityEventLog.record("SESSION_CLOSED", Severity.INFO, connection.username,
                                "Authenticated TLS connection closed.");
                    }
                }
                connection.close();
            } else {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // The peer may already have closed the TLS socket.
                }
            }
        }
    }

    private String authenticate(String line, ClientConnection connection) throws IOException {
        String[] fields = line == null ? new String[0] : line.split("\\t", 4);
        if (fields.length != 4 || !"AUTH".equals(fields[0])) {
            connection.send("AUTH_ERROR\tExpected account registration or login over TLS.");
            return null;
        }
        String action = fields[1];
        String username = fields[2];
        if (!AccountService.isValidUsername(username)) {
            connection.send("AUTH_ERROR\tInvalid account name.");
            return null;
        }

        final char[] password;
        try {
            byte[] encoded = Base64.getDecoder().decode(fields[3]);
            CharBuffer decoded = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(encoded));
            password = new char[decoded.remaining()];
            decoded.get(password);
            if (decoded.hasArray()) Arrays.fill(decoded.array(), '\0');
            Arrays.fill(encoded, (byte) 0);
        } catch (IllegalArgumentException exception) {
            connection.send("AUTH_ERROR\tInvalid credentials.");
            return null;
        }

        if ("REGISTER".equals(action)) {
            AccountService.RegistrationResult result = accounts.register(username, password);
            if (result != AccountService.RegistrationResult.CREATED) {
                SecurityEventLog.record("REGISTRATION_REJECTED", Severity.WARNING, username,
                        "Account registration was rejected: " + result.name().toLowerCase() + ".");
                connection.send("AUTH_ERROR\tRegistration failed: " + result.name().toLowerCase() + ".");
                return null;
            }
            SecurityEventLog.record("ACCOUNT_REGISTERED", Severity.INFO, username,
                    "Account created with a salted Argon2id password verifier.");
            return username;
        }
        if ("LOGIN".equals(action)) {
            AccountService.LoginResult result = accounts.authenticate(username, password);
            if (result == AccountService.LoginResult.AUTHENTICATED) {
                SecurityEventLog.record("LOGIN_SUCCEEDED", Severity.INFO, username,
                        "Account password verification succeeded.");
                return username;
            }
            if (result == AccountService.LoginResult.THROTTLED) {
                SecurityEventLog.record("LOGIN_THROTTLED", Severity.ALERT, username,
                        "Login blocked after repeated failed password attempts.");
                connection.send("AUTH_ERROR\tLogin failed. Too many failed attempts; login is temporarily blocked for 60 seconds.");
            } else {
                SecurityEventLog.record("AUTH_FAILED", Severity.WARNING, username,
                        "Account password verification failed.");
                connection.send("AUTH_ERROR\tLogin failed.");
            }
            return null;
        }
        Arrays.fill(password, '\0');
        connection.send("AUTH_ERROR\tAccount action must be REGISTER or LOGIN.");
        return null;
    }

    private void expireSessions() {
        long now = System.currentTimeMillis();
        for (ClientConnection connection : clients.values()) {
            if (connection.isExpired(now)) {
                SecurityEventLog.record("SESSION_EXPIRED", Severity.WARNING, connection.username,
                        "Session exceeded its idle or maximum lifetime.");
                try {
                    connection.send("SESSION_EXPIRED\tPlease log in again.");
                } catch (IOException ignored) {
                    // Closing the socket below still expires the server-side session.
                }
                connection.close();
            }
        }
    }

    private void handleKeyAnnouncement(ClientConnection sender, String line) throws IOException {
        String[] fields = line.split("\\t", 4);
        if (fields.length != 4) {
            SecurityEventLog.record("KEY_ANNOUNCEMENT_REJECTED", Severity.WARNING, sender.username,
                    "Malformed signed-key announcement was rejected.");
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
                    // A disconnected peer's handler removes it from the active map.
                }
            }
        }
    }

    private void handleMessage(ClientConnection sender, String line) throws IOException {
        String[] fields = line.split("\\t", 5);
        if (fields.length != 5 || !"SEND".equals(fields[0])) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Malformed message frame was rejected.");
            sender.send("ERROR\tExpected SEND, recipient, sequence, key version, and envelope.");
            return;
        }
        String recipientName = fields[1];
        if (!AccountService.isValidUsername(recipientName)) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Message with an invalid recipient name was rejected.");
            sender.send("ERROR\tRecipient name is invalid.");
            return;
        }

        final long sequence;
        final long keyVersion;
        try {
            sequence = Long.parseLong(fields[2]);
            keyVersion = Long.parseLong(fields[3]);
            if (sequence < 1 || keyVersion < 0) throw new NumberFormatException();
        } catch (NumberFormatException exception) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Message with an invalid sequence or key epoch was rejected.");
            sender.send("ERROR\tMessage sequence or key version was invalid.");
            return;
        }

        final String envelope;
        try {
            envelope = new String(Base64.getDecoder().decode(fields[4]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Message with an invalid envelope encoding was rejected.");
            sender.send("ERROR\tMessage envelope encoding was invalid.");
            return;
        }
        if (envelope.isBlank()) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Empty encrypted message envelope was rejected.");
            sender.send("ERROR\tMessage envelope cannot be empty.");
            return;
        }

        ClientConnection recipient = clients.get(recipientName);
        if (recipient == null) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Message delivery requested for an offline account.");
            sender.send("ERROR\t" + recipientName + " is not connected.");
            return;
        }

        String encodedEnvelope = Base64.getEncoder().encodeToString(envelope.getBytes(StandardCharsets.UTF_8));
        try {
            recipient.send("DELIVER\t" + sender.username + "\t" + sequence + "\t"
                    + keyVersion + "\t" + encodedEnvelope);
        } catch (IOException exception) {
            SecurityEventLog.record("MESSAGE_REJECTED", Severity.WARNING, sender.username,
                    "Message could not be delivered to the active recipient connection.");
            sender.send("ERROR\tCould not deliver message to " + recipientName + ".");
            return;
        }
        SecurityEventLog.record("MESSAGE_ROUTED", Severity.INFO, sender.username,
                "Encrypted message envelope routed to " + recipientName + " (sequence " + sequence + ").");
        sender.send("SENT\t" + recipientName);
    }

    private static final class ClientConnection {
        private final SSLSocket socket;
        private final BufferedReader input;
        private final BufferedWriter output;
        private volatile String username;
        private volatile long sessionStarted;
        private volatile long lastActivity;

        private ClientConnection(SSLSocket socket) throws IOException {
            this.socket = socket;
            this.input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        private synchronized void send(String line) throws IOException {
            output.write(line);
            output.newLine();
            output.flush();
        }

        private void startSession() {
            sessionStarted = System.currentTimeMillis();
            lastActivity = sessionStarted;
        }

        private void touch() {
            lastActivity = System.currentTimeMillis();
        }

        private boolean isExpired(long now) {
            return sessionStarted != 0 && (now - sessionStarted >= MAX_SESSION_AGE_MILLIS
                    || now - lastActivity >= IDLE_SESSION_MILLIS);
        }

        private void close() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // The peer may already have closed the TLS socket.
            }
        }
    }
}
