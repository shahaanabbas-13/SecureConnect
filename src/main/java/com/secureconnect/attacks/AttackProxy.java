package com.secureconnect.attacks;

import com.secureconnect.security.SecurityEventLog;
import com.secureconnect.security.SecurityEventLog.Severity;

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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/** Local-only attacker proxy for controlled demonstrations against SecureConnect. */
public final class AttackProxy {
    private final Mode mode;
    private final int listenPort;
    private final String targetHost;
    private final int targetPort;
    private final SSLContext proxyTlsContext;
    private final SSLContext upstreamTlsContext;
    private final AtomicBoolean attackApplied = new AtomicBoolean();
    private final AtomicBoolean replaySent = new AtomicBoolean();
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private static final int DOS_BURST_SIZE = 20;

    public AttackProxy(Mode mode, int listenPort, String targetHost, int targetPort,
                       SSLContext proxyTlsContext, SSLContext upstreamTlsContext) throws IOException {
        this.mode = mode;
        validatePort(listenPort);
        validatePort(targetPort);
        InetAddress target = InetAddress.getByName(targetHost);
        if (!target.isLoopbackAddress()) {
            throw new IllegalArgumentException("attack proxy target must be a loopback address");
        }
        this.listenPort = listenPort;
        this.targetHost = target.getHostAddress();
        this.targetPort = targetPort;
        this.proxyTlsContext = proxyTlsContext;
        this.upstreamTlsContext = upstreamTlsContext;
    }

    public void start() throws IOException {
        if (mode == Mode.DOS) {
            runDosBurst();
            workers.shutdownNow();
            return;
        }
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        SSLServerSocket tlsListener = (SSLServerSocket) proxyTlsContext.getServerSocketFactory()
                .createServerSocket(listenPort, 50, loopback);
        tlsListener.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        try (SSLServerSocket listener = tlsListener) {
            System.out.println("Attack proxy mode: " + mode.commandName);
            System.out.println("Clients connect to " + loopback.getHostAddress() + ":" + listenPort
                    + "; proxy forwards to " + targetHost + ":" + targetPort);
            System.out.println("Controlled localhost demonstration only. Press Ctrl+C to stop.");
            while (!listener.isClosed()) {
                SSLSocket client = (SSLSocket) listener.accept();
                client.setUseClientMode(false);
                workers.execute(() -> bridge(client));
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private void bridge(SSLSocket client) {
        try (client; SSLSocket server = (SSLSocket) upstreamTlsContext.getSocketFactory()
                .createSocket(targetHost, targetPort);
             BufferedReader clientInput = new BufferedReader(new InputStreamReader(
                     client.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter serverOutput = new BufferedWriter(new OutputStreamWriter(
                     server.getOutputStream(), StandardCharsets.UTF_8));
             BufferedReader serverInput = new BufferedReader(new InputStreamReader(
                     server.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter clientOutput = new BufferedWriter(new OutputStreamWriter(
                     client.getOutputStream(), StandardCharsets.UTF_8))) {
            SSLParameters parameters = server.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            server.setSSLParameters(parameters);
            server.startHandshake();
            client.startHandshake();
            AtomicReference<String> clientNameRef = new AtomicReference<>("unknown client");
            AtomicBoolean masqueradeJoin = new AtomicBoolean();
            Thread serverToClient = new Thread(() -> forward(serverInput, clientOutput,
                    clientNameRef, masqueradeJoin),
                    "secureconnect-attack-downstream");
            serverToClient.setDaemon(true);
            serverToClient.start();

            String clientName = "unknown client";
            String line;
            while ((line = clientInput.readLine()) != null) {
                if (line.startsWith("AUTH\t")) {
                    String[] authFields = line.split("\\t", 4);
                    if (authFields.length == 4) clientName = authFields[2];
                    clientNameRef.set(clientName);
                    if (mode == Mode.MASQUERADE && "Mallory".equals(clientName)) {
                        if ("LOGIN".equals(authFields[1])) {
                            authFields[2] = "Alice";
                            line = String.join("\t", authFields);
                            masqueradeJoin.set(true);
                            System.out.println("[MASQUERADE] Changed Mallory's login name to Alice; the server checks Alice's password.");
                            SecurityEventLog.record("ATTACK_MASQUERADE", Severity.ALERT, "Mallory",
                                    "Changed the claimed login name to Alice; relay password verification should reject the request.");
                        } else {
                            System.out.println("[MASQUERADE] Only a login attempt is rewritten; account registration is not altered.");
                        }
                    }
                }
                String transformed = transform(line, clientName);
                serverOutput.write(transformed);
                serverOutput.newLine();
                serverOutput.flush();

                if (mode == Mode.REPLAY && transformed.startsWith("SEND\t")
                        && attackApplied.get() && replaySent.compareAndSet(false, true)) {
                    // Duplicate only the first captured request, after forwarding the original.
                    serverOutput.write(transformed);
                    serverOutput.newLine();
                    serverOutput.flush();
                    System.out.println("[REPLAY] Re-sent one captured SEND frame from " + clientName + ".");
                }
            }
            server.shutdownOutput();
            serverToClient.join(1500);
        } catch (IOException exception) {
            if (!"Socket closed".equals(exception.getMessage())) {
                System.out.println("[PROXY] Connection ended: " + exception.getMessage());
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private String transform(String line, String clientName) {
        if (mode == Mode.EAVESDROP && line.startsWith("SEND\t")) {
            String[] fields = line.split("\\t", 5);
            if (fields.length == 5) {
                int bytes = fields[4].length();
                System.out.println("[EAVESDROP] " + clientName + " -> " + fields[1]
                        + ", sequence=" + fields[2] + ", keyVersion=" + fields[3]
                        + ", encoded envelope=" + bytes + " characters; no plaintext observed.");
                SecurityEventLog.record("ATTACK_EAVESDROP", Severity.WARNING, clientName,
                        "Observed encrypted message metadata for " + fields[1] + " (sequence "
                                + fields[2] + "); plaintext was not available.");
            }
            return line;
        }

        if (mode == Mode.TAMPER && line.startsWith("SEND\t")
                && attackApplied.compareAndSet(false, true)) {
            String changed = tamperEnvelope(line);
            if (changed != null) {
                System.out.println("[TAMPER] Altered the first ciphertext before it reached the relay.");
                SecurityEventLog.record("ATTACK_TAMPER", Severity.ALERT, clientName,
                        "Modified one encrypted message envelope before relay delivery.");
                return changed;
            }
            attackApplied.set(false);
        }

        if (mode == Mode.REPLAY && line.startsWith("SEND\t")
                && attackApplied.compareAndSet(false, true)) {
            System.out.println("[REPLAY] Captured the first SEND frame for duplicate delivery.");
            SecurityEventLog.record("ATTACK_REPLAY", Severity.ALERT, clientName,
                    "Captured a SEND frame for one duplicate replay attempt.");
        }

        if (mode == Mode.KEY_SUBSTITUTION && line.startsWith("KEY\t")
                && attackApplied.compareAndSet(false, true)) {
            String changed = tamperSignature(line);
            if (changed != null) {
                System.out.println("[KEY-SUBSTITUTION] Changed a signed ephemeral-key announcement.");
                SecurityEventLog.record("ATTACK_KEY_SUBSTITUTION", Severity.ALERT, clientName,
                        "Modified a signed ephemeral-key announcement.");
                return changed;
            }
            attackApplied.set(false);
        }
        return line;
    }

    private static String tamperEnvelope(String line) {
        String[] fields = line.split("\\t", 5);
        if (fields.length != 5) {
            return null;
        }
        try {
            String envelope = new String(Base64.getDecoder().decode(fields[4]), StandardCharsets.UTF_8);
            if (!envelope.startsWith("SC1.")) {
                return null;
            }
            byte[] bytes = Base64.getDecoder().decode(envelope.substring(4));
            // Envelope layout: 12-byte GCM nonce, ciphertext, then 16-byte authentication tag.
            if (bytes.length <= 28) {
                return null;
            }
            bytes[12] ^= 0x01;
            String alteredEnvelope = "SC1." + Base64.getEncoder().encodeToString(bytes);
            fields[4] = Base64.getEncoder().encodeToString(
                    alteredEnvelope.getBytes(StandardCharsets.UTF_8));
            return String.join("\t", fields);
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private static String tamperSignature(String line) {
        String[] fields = line.split("\\t", 4);
        if (fields.length != 4 || fields[3].isEmpty()) {
            return null;
        }
        char first = fields[3].charAt(0);
        fields[3] = (first == 'A' ? "B" : "A") + fields[3].substring(1);
        return String.join("\t", fields);
    }

    private void forward(BufferedReader input, BufferedWriter output,
                         AtomicReference<String> clientName, AtomicBoolean masqueradeJoin) {
        try {
            String line;
            while ((line = input.readLine()) != null) {
                if (mode == Mode.MASQUERADE && masqueradeJoin.get()
                        && line.startsWith("AUTH_ERROR\t")) {
                    System.out.println("[MASQUERADE] Relay rejected the login because Mallory did not know Alice's password.");
                }
                output.write(line);
                output.newLine();
                output.flush();
            }
        } catch (IOException ignored) {
            // The client may have closed the connection first.
        }
    }

    private void runDosBurst() throws IOException {
        System.out.println("[DOS] Sending a bounded burst of " + DOS_BURST_SIZE
                + " concurrent localhost connections to " + targetHost + ":" + targetPort + ".");
        System.out.println("This relay has no connection rate limit yet; this is a small baseline only.");
        SecurityEventLog.record("ATTACK_DOS_BASELINE", Severity.WARNING, "attack-lab",
                "Started a bounded burst of " + DOS_BURST_SIZE + " local TLS authentication probes.");
        CountDownLatch connected = new CountDownLatch(DOS_BURST_SIZE);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        Future<?>[] attempts = new Future<?>[DOS_BURST_SIZE];
        for (int index = 0; index < DOS_BURST_SIZE; index++) {
            String username = "LoadProbe" + index;
            attempts[index] = workers.submit(() -> {
                try (SSLSocket socket = (SSLSocket) upstreamTlsContext.getSocketFactory()
                        .createSocket(targetHost, targetPort);
                     BufferedWriter output = new BufferedWriter(new OutputStreamWriter(
                             socket.getOutputStream(), StandardCharsets.UTF_8));
                     BufferedReader input = new BufferedReader(new InputStreamReader(
                             socket.getInputStream(), StandardCharsets.UTF_8))) {
                    SSLParameters parameters = socket.getSSLParameters();
                    parameters.setEndpointIdentificationAlgorithm("HTTPS");
                    socket.setSSLParameters(parameters);
                    socket.startHandshake();
                    output.write("INVALID_AUTH\t" + username);
                    output.newLine();
                    output.flush();
                    String response = input.readLine();
                    if (response != null && response.startsWith("AUTH_ERROR\t")) {
                        accepted.incrementAndGet();
                    }
                    connected.countDown();
                    release.await();
                    output.write("QUIT");
                    output.newLine();
                    output.flush();
                } catch (IOException exception) {
                    connected.countDown();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    connected.countDown();
                }
            });
        }
        try {
            connected.await();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } finally {
            release.countDown();
        }
        for (Future<?> attempt : attempts) {
            try {
                attempt.get();
            } catch (Exception ignored) {
                // Report completed accepts below; this is a bounded demonstration.
            }
        }
        System.out.println("[DOS] TLS relay completed " + accepted.get() + " of " + DOS_BURST_SIZE
                + " unauthenticated handshake/request attempts.");
        System.out.println("No crash or resource exhaustion was attempted.");
        SecurityEventLog.record("ATTACK_DOS_BASELINE_COMPLETE", Severity.INFO, "attack-lab",
                "Relay completed " + accepted.get() + " of " + DOS_BURST_SIZE + " bounded probes.");
    }

    private static void validatePort(int port) {
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
    }

    public enum Mode {
        EAVESDROP("eavesdrop"),
        TAMPER("tamper"),
        REPLAY("replay"),
        KEY_SUBSTITUTION("key-substitution"),
        MASQUERADE("masquerade"),
        DOS("dos");

        private final String commandName;

        Mode(String commandName) {
            this.commandName = commandName;
        }

        public static Mode parse(String value) {
            for (Mode mode : values()) {
                if (mode.commandName.equalsIgnoreCase(value)) {
                    return mode;
                }
            }
            throw new IllegalArgumentException("mode must be eavesdrop, tamper, replay, key-substitution, masquerade, or dos");
        }
    }
}
