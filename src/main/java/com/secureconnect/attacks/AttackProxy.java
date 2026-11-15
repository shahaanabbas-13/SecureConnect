package com.secureconnect.attacks;

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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** Local-only attacker proxy for controlled demonstrations against SecureConnect. */
public final class AttackProxy {
    private final Mode mode;
    private final int listenPort;
    private final String targetHost;
    private final int targetPort;
    private final AtomicBoolean attackApplied = new AtomicBoolean();
    private final AtomicBoolean replaySent = new AtomicBoolean();
    private final ExecutorService workers = Executors.newCachedThreadPool();

    public AttackProxy(Mode mode, int listenPort, String targetHost, int targetPort) throws IOException {
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
    }

    public void start() throws IOException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (ServerSocket listener = new ServerSocket(listenPort, 50, loopback)) {
            System.out.println("Attack proxy mode: " + mode.commandName);
            System.out.println("Clients connect to " + loopback.getHostAddress() + ":" + listenPort
                    + "; proxy forwards to " + targetHost + ":" + targetPort);
            System.out.println("Controlled localhost demonstration only. Press Ctrl+C to stop.");
            while (!listener.isClosed()) {
                Socket client = listener.accept();
                workers.execute(() -> bridge(client));
            }
        } finally {
            workers.shutdownNow();
        }
    }

    private void bridge(Socket client) {
        try (client; Socket server = new Socket(targetHost, targetPort);
             BufferedReader clientInput = new BufferedReader(new InputStreamReader(
                     client.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter serverOutput = new BufferedWriter(new OutputStreamWriter(
                     server.getOutputStream(), StandardCharsets.UTF_8));
             BufferedReader serverInput = new BufferedReader(new InputStreamReader(
                     server.getInputStream(), StandardCharsets.UTF_8));
             BufferedWriter clientOutput = new BufferedWriter(new OutputStreamWriter(
                     client.getOutputStream(), StandardCharsets.UTF_8))) {
            Thread serverToClient = new Thread(() -> forward(serverInput, clientOutput),
                    "secureconnect-attack-downstream");
            serverToClient.setDaemon(true);
            serverToClient.start();

            String clientName = "unknown client";
            String line;
            while ((line = clientInput.readLine()) != null) {
                if (line.startsWith("JOIN\t")) {
                    clientName = line.substring("JOIN\t".length());
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
            }
            return line;
        }

        if (mode == Mode.TAMPER && line.startsWith("SEND\t")
                && attackApplied.compareAndSet(false, true)) {
            String changed = tamperEnvelope(line);
            if (changed != null) {
                System.out.println("[TAMPER] Altered the first ciphertext before it reached the relay.");
                return changed;
            }
            attackApplied.set(false);
        }

        if (mode == Mode.REPLAY && line.startsWith("SEND\t")
                && attackApplied.compareAndSet(false, true)) {
            System.out.println("[REPLAY] Captured the first SEND frame for duplicate delivery.");
        }

        if (mode == Mode.KEY_SUBSTITUTION && line.startsWith("KEY\t")
                && attackApplied.compareAndSet(false, true)) {
            String changed = tamperSignature(line);
            if (changed != null) {
                System.out.println("[KEY-SUBSTITUTION] Changed a signed ephemeral-key announcement.");
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

    private static void forward(BufferedReader input, BufferedWriter output) {
        try {
            String line;
            while ((line = input.readLine()) != null) {
                output.write(line);
                output.newLine();
                output.flush();
            }
        } catch (IOException ignored) {
            // The client may have closed the connection first.
        }
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
        KEY_SUBSTITUTION("key-substitution");

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
            throw new IllegalArgumentException("mode must be eavesdrop, tamper, replay, or key-substitution");
        }
    }
}
