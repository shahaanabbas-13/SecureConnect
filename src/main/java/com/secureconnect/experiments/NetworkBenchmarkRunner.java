package com.secureconnect.experiments;

import com.secureconnect.crypto.MessageKeySchedule;
import com.secureconnect.keymanagement.IdentityKeys;
import com.secureconnect.keymanagement.SessionKeyExchange;
import com.secureconnect.security.TlsContexts;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Measures a real client-to-client encrypted message delivery through the local TLS relay. */
public final class NetworkBenchmarkRunner {
    private static final int[] PAYLOAD_SIZES = {1_024, 10_240, 102_400, 1_048_576};
    private static final int DEFAULT_ITERATIONS = 100;
    private static final int WARMUP_ITERATIONS = 10;
    private static final int SOCKET_TIMEOUT_MILLIS = 30_000;
    private static final Path OUTPUT_DIRECTORY = Path.of("experiments", "results");
    private static final DateTimeFormatter STAMP = DateTimeFormatter
            .ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());

    private NetworkBenchmarkRunner() { }

    public static void run(String[] args) throws IOException {
        if (args.length < 3 || args.length > 6) {
            throw new IllegalArgumentException("network-benchmark syntax: network-benchmark <sender> <receiver> [iterations] [host] [port]");
        }
        String senderName = validateUsername(args[1]);
        String receiverName = validateUsername(args[2]);
        if (senderName.equalsIgnoreCase(receiverName)) {
            throw new IllegalArgumentException("sender and receiver must be different accounts");
        }
        int iterations = args.length >= 4 ? parseIterations(args[3]) : DEFAULT_ITERATIONS;
        String host = args.length >= 5 ? args[4] : "127.0.0.1";
        int port = args.length >= 6 ? parsePort(args[5]) : 5050;
        if (!InetAddress.getByName(host).isLoopbackAddress()) {
            throw new IllegalArgumentException("network benchmark is restricted to a localhost relay");
        }

        char[] senderPassword = null;
        char[] receiverPassword = null;
        String runId = STAMP.format(Instant.now()) + "-" + UUID.randomUUID().toString().substring(0, 8);
        Files.createDirectories(OUTPUT_DIRECTORY);
        Path rawPath = OUTPUT_DIRECTORY.resolve("secureconnect-network-" + runId + "-raw.csv");
        Path summaryPath = OUTPUT_DIRECTORY.resolve("secureconnect-network-" + runId + "-summary.csv");
        Path metadataPath = OUTPUT_DIRECTORY.resolve("secureconnect-network-" + runId + "-metadata.txt");
        byte[] senderRoot = null;
        byte[] receiverRoot = null;
        MessageKeySchedule senderSchedule = null;
        MessageKeySchedule receiverSchedule = null;
        List<Summary> summaries = new ArrayList<>();
        long[] sequence = {1};

        try {
            senderPassword = readPassword(senderName);
            receiverPassword = readPassword(receiverName);
            SSLContext tls = TlsContexts.clientContextFromEnvironment();
            PrivateKey senderIdentity = IdentityKeys.loadPrivate(senderName);
            PrivateKey receiverIdentity = IdentityKeys.loadPrivate(receiverName);
            PublicKey senderTrustsReceiver = IdentityKeys.decodePinnedPublicKey(
                    Files.readString(IdentityKeys.publicPath(receiverName), StandardCharsets.UTF_8));
            PublicKey receiverTrustsSender = IdentityKeys.decodePinnedPublicKey(
                    Files.readString(IdentityKeys.publicPath(senderName), StandardCharsets.UTF_8));
            SessionKeyExchange.LocalSession senderLocal = SessionKeyExchange.start(senderName, senderIdentity);
            SessionKeyExchange.LocalSession receiverLocal = SessionKeyExchange.start(receiverName, receiverIdentity);

            try (Peer sender = Peer.connect(tls, host, port, senderName, senderPassword, senderLocal);
                 Peer receiver = Peer.connect(tls, host, port, receiverName, receiverPassword, receiverLocal);
                 BufferedWriter raw = Files.newBufferedWriter(rawPath, StandardCharsets.UTF_8,
                         StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                senderPassword = null;
                receiverPassword = null;
                PeerAnnouncement senderSeesReceiver = sender.readPeerAnnouncement(receiverName);
                PeerAnnouncement receiverSeesSender = receiver.readPeerAnnouncement(senderName);
                senderRoot = SessionKeyExchange.deriveSessionKey(senderName, receiverName, senderLocal,
                        senderSeesReceiver.sessionId(), senderSeesReceiver.ephemeralKey(),
                        senderSeesReceiver.signature(), senderTrustsReceiver);
                receiverRoot = SessionKeyExchange.deriveSessionKey(receiverName, senderName, receiverLocal,
                        receiverSeesSender.sessionId(), receiverSeesSender.ephemeralKey(),
                        receiverSeesSender.signature(), receiverTrustsSender);
                if (!MessageDigest.isEqual(senderRoot, receiverRoot)) {
                    throw new SecurityException("sender and receiver derived different session keys");
                }
                senderSchedule = new MessageKeySchedule(senderRoot, senderName, receiverName);
                receiverSchedule = new MessageKeySchedule(receiverRoot, receiverName, senderName);

                raw.write("run_id,payload_bytes,sample_index,sender_encrypt_encode_ns,send_to_delivery_ns,receiver_decode_decrypt_ns,send_to_decrypt_ns,post_decrypt_relay_ack_wait_ns,throughput_mib_per_sec\n");
                for (int payloadSize : PAYLOAD_SIZES) {
                    String plaintext = "M".repeat(payloadSize);
                    for (int warmup = 0; warmup < WARMUP_ITERATIONS; warmup++) {
                        exchange(sender, receiver, senderSchedule, receiverSchedule, senderName,
                                receiverName, plaintext, sequence[0]++);
                    }
                    List<Measurement> samples = new ArrayList<>(iterations);
                    for (int sample = 0; sample < iterations; sample++) {
                        Measurement measurement = exchange(sender, receiver, senderSchedule, receiverSchedule,
                                senderName, receiverName, plaintext, sequence[0]++);
                        samples.add(measurement);
                        long elapsed = measurement.endToDecryptNs();
                        double throughput = ((double) payloadSize / (1024.0 * 1024.0))
                                / (elapsed / 1_000_000_000.0);
                        raw.write(String.format(Locale.ROOT, "%s,%d,%d,%d,%d,%d,%d,%d,%.6f%n",
                                runId, payloadSize, sample + 1, measurement.encryptPrepareNs(),
                                measurement.sendToDeliveryNs(), measurement.receiverDecryptNs(),
                                measurement.endToDecryptNs(), measurement.relayAckWaitNs(), throughput));
                    }
                    raw.flush();
                    summaries.add(Summary.from(payloadSize, samples));
                }
            }
            writeSummary(summaryPath, runId, iterations, summaries);
            writeMetadata(metadataPath, runId, senderName, receiverName, host, port, iterations);
        } catch (IOException | RuntimeException | Error exception) {
            Files.deleteIfExists(rawPath);
            Files.deleteIfExists(summaryPath);
            Files.deleteIfExists(metadataPath);
            throw exception;
        } finally {
            if (senderPassword != null) Arrays.fill(senderPassword, '\0');
            if (receiverPassword != null) Arrays.fill(receiverPassword, '\0');
            if (senderRoot != null) Arrays.fill(senderRoot, (byte) 0);
            if (receiverRoot != null) Arrays.fill(receiverRoot, (byte) 0);
            if (senderSchedule != null) senderSchedule.clear();
            if (receiverSchedule != null) receiverSchedule.clear();
        }

        System.out.println("SecureConnect TLS-relay end-to-end benchmark complete.");
        System.out.println("Run ID: " + runId + " (" + iterations + " samples and "
                + WARMUP_ITERATIONS + " warm-ups per payload)");
        for (Summary summary : summaries) {
            System.out.printf(Locale.ROOT,
                    "%7s  mean %9.2f µs  median %9.2f µs  p95 %9.2f µs  throughput %8.2f MiB/s%n",
                    formatSize(summary.payloadBytes()), summary.meanNs() / 1_000.0,
                    summary.medianNs() / 1_000.0, summary.p95Ns() / 1_000.0,
                    summary.throughputMiBPerSecond());
            System.out.printf(Locale.ROOT,
                    "         phase means (µs): sender %.2f | relay delivery %.2f | receiver decrypt %.2f | post-delivery ack %.2f%n",
                    summary.meanEncryptPrepareNs() / 1_000.0, summary.meanSendToDeliveryNs() / 1_000.0,
                    summary.meanReceiverDecryptNs() / 1_000.0, summary.meanRelayAckWaitNs() / 1_000.0);
        }
        System.out.println("Raw samples: " + rawPath.toAbsolutePath());
        System.out.println("Summary:     " + summaryPath.toAbsolutePath());
        System.out.println("Metadata:    " + metadataPath.toAbsolutePath());
        System.out.println("Latency covers sender encryption, TLS socket I/O, relay routing, and receiver decryption.");
        System.out.println("Account login and session-key establishment are excluded from measured samples.");
    }

    private static Measurement exchange(Peer sender, Peer receiver, MessageKeySchedule senderSchedule,
                                        MessageKeySchedule receiverSchedule, String senderName,
                                        String receiverName, String plaintext, long sequence) throws IOException {
        long version = senderSchedule.keyVersionFor(sequence);
        long started = System.nanoTime();
        String envelope = senderSchedule.encrypt(plaintext, sequence);
        String encoded = Base64.getEncoder().encodeToString(envelope.getBytes(StandardCharsets.UTF_8));
        long encryptPrepareDone = System.nanoTime();
        long sendStarted = System.nanoTime();
        sender.write("SEND\t" + receiverName + "\t" + sequence + "\t" + version + "\t" + encoded);

        String delivered = receiver.readLine();
        long deliveryReceived = System.nanoTime();
        String[] fields = delivered == null ? new String[0] : delivered.split("\\t", 5);
        if (fields.length != 5 || !"DELIVER".equals(fields[0]) || !senderName.equals(fields[1])) {
            throw new IOException("relay returned an unexpected delivery frame");
        }
        long receivedSequence;
        long receivedVersion;
        try {
            receivedSequence = Long.parseLong(fields[2]);
            receivedVersion = Long.parseLong(fields[3]);
        } catch (NumberFormatException exception) {
            throw new IOException("relay returned invalid message sequence metadata", exception);
        }
        if (receivedSequence != sequence || receivedVersion != version) {
            throw new IOException("relay changed message sequence or key version");
        }
        final String encodedEnvelope;
        try {
            encodedEnvelope = new String(Base64.getDecoder().decode(fields[4]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            throw new IOException("relay returned a malformed message envelope", exception);
        }
        String receivedPlaintext;
        try {
            receivedPlaintext = receiverSchedule.decrypt(encodedEnvelope, senderName, sequence, version);
        } catch (IllegalArgumentException | SecurityException exception) {
            throw new IOException("receiver rejected the benchmark message", exception);
        }
        if (!plaintext.equals(receivedPlaintext)) {
            throw new IOException("receiver plaintext did not match the sent benchmark message");
        }
        long decryptedAt = System.nanoTime();

        long ackWaitStarted = System.nanoTime();
        String acknowledgement = sender.readLine();
        long ackReceived = System.nanoTime();
        if (!("SENT\t" + receiverName).equals(acknowledgement)) {
            throw new IOException("relay did not acknowledge the delivered message");
        }
        return new Measurement(encryptPrepareDone - started, deliveryReceived - sendStarted,
                decryptedAt - deliveryReceived, decryptedAt - started, ackReceived - ackWaitStarted);
    }

    private static void writeSummary(Path path, String runId, int iterations,
                                     List<Summary> summaries) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writer.write("run_id,payload_bytes,sample_count,warmup_iterations,mean_ns,median_ns,p95_ns,std_dev_ns,mean_throughput_mib_per_sec,mean_sender_encrypt_encode_ns,mean_relay_delivery_ns,mean_receiver_decrypt_ns,mean_post_delivery_ack_wait_ns\n");
            for (Summary row : summaries) {
                writer.write(String.format(Locale.ROOT, "%s,%d,%d,%d,%.2f,%.2f,%.2f,%.2f,%.6f,%.2f,%.2f,%.2f,%.2f%n",
                        runId, row.payloadBytes(), iterations, WARMUP_ITERATIONS, row.meanNs(),
                        row.medianNs(), row.p95Ns(), row.standardDeviationNs(),
                        row.throughputMiBPerSecond(), row.meanEncryptPrepareNs(),
                        row.meanSendToDeliveryNs(), row.meanReceiverDecryptNs(), row.meanRelayAckWaitNs()));
            }
        }
    }

    private static void writeMetadata(Path path, String runId, String sender, String receiver,
                                      String host, int port, int iterations) throws IOException {
        String metadata = "SecureConnect local TLS relay end-to-end benchmark\n"
                + "Run ID: " + runId + "\n"
                + "Generated: " + Instant.now() + "\n"
                + "Sender account: " + sender + "\n"
                + "Receiver account: " + receiver + "\n"
                + "Relay endpoint: " + host + ":" + port + " (loopback only)\n"
                + "Java version: " + System.getProperty("java.version") + "\n"
                + "Java VM: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version") + "\n"
                + "Operating system: " + System.getProperty("os.name") + " " + System.getProperty("os.version") + "\n"
                + "Architecture: " + System.getProperty("os.arch") + "\n"
                + "Available processors: " + Runtime.getRuntime().availableProcessors() + "\n"
                + "Payload sizes bytes: " + Arrays.toString(PAYLOAD_SIZES) + "\n"
                + "Measured samples per payload: " + iterations + "\n"
                + "Warm-up messages per payload: " + WARMUP_ITERATIONS + "\n"
                + "Measurement: System.nanoTime from before sender encryption through receiver authentication/decryption.\n"
                + "Raw phase timings: sender encryption plus envelope encoding; send-to-DELIVER; receiver frame decode/decrypt; post-decrypt SENT acknowledgement wait.\n"
                + "Includes: sender crypto, TLS socket I/O, loopback TCP, relay routing, receiver TLS and decrypt.\n"
                + "Excludes: account login, TLS connection setup, signed X25519 key exchange, warm-up messages, and the per-message audit append.\n"
                + "After the timed receiver decrypt, the runner waits for the relay SENT acknowledgement; the relay emits it only after its audit append, keeping that work outside the next sample.\n"
                + "Throughput uses plaintext payload bytes per one-way send-to-decrypt latency.\n";
        Files.writeString(path, metadata, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static char[] readPassword(String username) {
        String variable = "SECURECONNECT_BENCHMARK_"
                + username.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_") + "_PASSWORD";
        String fromEnvironment = System.getenv(variable);
        if (fromEnvironment != null) return fromEnvironment.toCharArray();
        Console console = System.console();
        if (console == null) {
            throw new IllegalArgumentException("no interactive console; provide " + variable
                    + " in the process environment");
        }
        char[] password = console.readPassword("Password for benchmark account %s: ", username);
        if (password == null) throw new IllegalArgumentException("password was not provided for " + username);
        return password;
    }

    private static String encodePassword(char[] password) {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        Arrays.fill(password, '\0');
        try {
            return Base64.getEncoder().encodeToString(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
        }
    }

    private static String validateUsername(String username) {
        if (username == null || !username.matches("[A-Za-z0-9_-]{1,32}")) {
            throw new IllegalArgumentException("account names must use 1-32 letters, digits, underscores, or hyphens");
        }
        return username;
    }

    private static int parseIterations(String value) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1 || parsed > 10_000) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("iterations must be between 1 and 10000");
        }
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) throw new NumberFormatException();
            return port;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }
    }

    private static String formatSize(int bytes) {
        return bytes >= 1_048_576 ? (bytes / 1_048_576) + " MB" : (bytes / 1_024) + " KB";
    }

    private record PeerAnnouncement(String sessionId, String ephemeralKey, String signature) { }

    private static final class Peer implements AutoCloseable {
        private final String username;
        private final SSLSocket socket;
        private final BufferedReader input;
        private final BufferedWriter output;

        private Peer(String username, SSLSocket socket) throws IOException {
            this.username = username;
            this.socket = socket;
            this.input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));
        }

        static Peer connect(SSLContext tls, String host, int port, String username,
                            char[] password, SessionKeyExchange.LocalSession localSession) throws IOException {
            String encodedPassword = encodePassword(password);
            SSLSocket socket = (SSLSocket) tls.getSocketFactory().createSocket(host, port);
            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            Peer peer = new Peer(username, socket);
            try {
                socket.startHandshake();
                peer.write("AUTH\tLOGIN\t" + username + "\t" + encodedPassword);
                String response = peer.readLine();
                if (!("AUTH_OK\t" + username).equals(response)) {
                    String reason = response != null && response.startsWith("AUTH_ERROR\t")
                            ? response.substring("AUTH_ERROR\t".length()) : "unexpected relay authentication response";
                    throw new IOException("TLS relay login failed for " + username + ": " + reason);
                }
                peer.write(localSession.announcement());
                return peer;
            } catch (IOException | RuntimeException exception) {
                peer.close();
                throw exception;
            } finally {
                encodedPassword = "";
            }
        }

        PeerAnnouncement readPeerAnnouncement(String expectedPeer) throws IOException {
            socket.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
            String line = readLine();
            String[] fields = line == null ? new String[0] : line.split("\\t", 5);
            if (fields.length != 5 || !"PEERKEY".equals(fields[0]) || !expectedPeer.equals(fields[1])) {
                throw new IOException("expected signed key announcement from " + expectedPeer
                        + " but received an unexpected relay frame");
            }
            return new PeerAnnouncement(fields[2], fields[3], fields[4]);
        }

        void write(String line) throws IOException {
            output.write(line);
            output.newLine();
            output.flush();
        }

        String readLine() throws IOException { return input.readLine(); }

        @Override
        public void close() {
            try {
                if (!socket.isClosed()) {
                    write("LOGOUT");
                    socket.setSoTimeout(2_000);
                    readLine();
                }
            } catch (IOException ignored) {
                // The relay or peer may already have closed this local benchmark connection.
            } finally {
                try { socket.close(); } catch (IOException ignored) { }
            }
        }
    }

    private record Measurement(long encryptPrepareNs, long sendToDeliveryNs, long receiverDecryptNs,
                               long endToDecryptNs, long relayAckWaitNs) { }

    private record Summary(int payloadBytes, double meanNs, double medianNs, double p95Ns,
                           double standardDeviationNs, double throughputMiBPerSecond,
                           double meanEncryptPrepareNs, double meanSendToDeliveryNs,
                           double meanReceiverDecryptNs, double meanRelayAckWaitNs) {
        static Summary from(int payloadBytes, List<Measurement> measurements) {
            long[] samples = measurements.stream().mapToLong(Measurement::endToDecryptNs).toArray();
            long[] sorted = samples.clone();
            Arrays.sort(sorted);
            double mean = Arrays.stream(samples).average().orElseThrow();
            double variance = Arrays.stream(samples).mapToDouble(value -> (value - mean) * (value - mean))
                    .sum() / Math.max(1, samples.length - 1);
            double median = sorted.length % 2 == 0
                    ? (sorted[sorted.length / 2 - 1] / 2.0 + sorted[sorted.length / 2] / 2.0)
                    : sorted[sorted.length / 2];
            int p95Index = Math.max(0, (int) Math.ceil(sorted.length * 0.95) - 1);
            double throughput = ((double) payloadBytes / (1024.0 * 1024.0))
                    / (mean / 1_000_000_000.0);
            return new Summary(payloadBytes, mean, median, sorted[p95Index], Math.sqrt(variance), throughput,
                    meanPhase(measurements, Measurement::encryptPrepareNs),
                    meanPhase(measurements, Measurement::sendToDeliveryNs),
                    meanPhase(measurements, Measurement::receiverDecryptNs),
                    meanPhase(measurements, Measurement::relayAckWaitNs));
        }

        private static double meanPhase(List<Measurement> samples,
                                        java.util.function.ToLongFunction<Measurement> phase) {
            return samples.stream().mapToLong(phase).average().orElse(0);
        }
    }
}
