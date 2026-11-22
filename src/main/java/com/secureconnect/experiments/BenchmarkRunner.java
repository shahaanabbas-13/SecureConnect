package com.secureconnect.experiments;

import com.secureconnect.crypto.MessageKeySchedule;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Reproducible local microbenchmark for the plaintext copy baseline and protected message crypto. */
public final class BenchmarkRunner {
    private static final int[] PAYLOAD_SIZES = {1_024, 10_240, 102_400, 1_048_576};
    private static final Path DEFAULT_OUTPUT_DIRECTORY = Path.of("experiments", "results");
    private static final DateTimeFormatter RUN_STAMP = DateTimeFormatter
            .ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());
    private static volatile Object benchmarkSink;

    private BenchmarkRunner() { }

    public static void run(String[] args) throws IOException {
        int iterations = args.length >= 2 ? parsePositive(args[1], "iterations", 10_000) : 100;
        int warmup = args.length >= 3 ? parseNonnegative(args[2], "warm-up iterations", 1_000) : 100;
        Path outputDirectory = args.length >= 4 ? Path.of(args[3]) : DEFAULT_OUTPUT_DIRECTORY;
        if (args.length > 4) {
            throw new IllegalArgumentException("benchmark syntax: benchmark [iterations] [warmup] [output-directory]");
        }

        Files.createDirectories(outputDirectory);
        String runId = RUN_STAMP.format(Instant.now()) + "-" + UUID.randomUUID().toString().substring(0, 8);
        Path rawPath = outputDirectory.resolve("secureconnect-" + runId + "-raw.csv");
        Path summaryPath = outputDirectory.resolve("secureconnect-" + runId + "-summary.csv");
        Path metadataPath = outputDirectory.resolve("secureconnect-" + runId + "-metadata.txt");
        byte[] sessionRootKey = new byte[32];
        new SecureRandom().nextBytes(sessionRootKey);
        List<Summary> summaries = new ArrayList<>();

        try (BufferedWriter raw = Files.newBufferedWriter(rawPath, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            raw.write("run_id,payload_bytes,metric,sample_index,elapsed_ns,processed_bytes,throughput_mib_per_sec\n");
            for (int payloadSize : PAYLOAD_SIZES) {
                byte[] plaintextBytes = new byte[payloadSize];
                Arrays.fill(plaintextBytes, (byte) 'S');
                String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
                MessageKeySchedule senderSchedule = new MessageKeySchedule(
                        sessionRootKey, "BenchmarkAlice", "BenchmarkBob");
                MessageKeySchedule receiverSchedule = new MessageKeySchedule(
                        sessionRootKey, "BenchmarkBob", "BenchmarkAlice");
                String encryptedForDecrypt = senderSchedule.encrypt(plaintext, 1);
                long[] sequence = {1};
                List<TimedOperation> operations = List.of(
                        () -> benchmarkSink = Arrays.copyOf(plaintextBytes, plaintextBytes.length),
                        () -> benchmarkSink = senderSchedule.encrypt(plaintext, 1),
                        () -> {
                            String decoded = receiverSchedule.decrypt(encryptedForDecrypt, "BenchmarkAlice", 1, 0);
                            if (!plaintext.equals(decoded)) throw new IllegalStateException("decryption result mismatch");
                            benchmarkSink = decoded;
                        },
                        () -> {
                            long currentSequence = sequence[0]++;
                            long version = senderSchedule.keyVersionFor(currentSequence);
                            String envelope = senderSchedule.encrypt(plaintext, currentSequence);
                            String decoded = receiverSchedule.decrypt(envelope, "BenchmarkAlice", currentSequence, version);
                            if (!plaintext.equals(decoded)) throw new IllegalStateException("round-trip result mismatch");
                            benchmarkSink = decoded;
                        });
                String[] metricNames = {"plaintext_copy_baseline", "protected_encrypt",
                        "protected_decrypt", "protected_round_trip"};
                long[][] samples = measureInterleaved(raw, runId, payloadSize, metricNames,
                        iterations, warmup, operations);
                for (int metric = 0; metric < metricNames.length; metric++) {
                    summaries.add(Summary.from(payloadSize, metricNames[metric], iterations,
                            warmup, samples[metric]));
                }
                senderSchedule.clear();
                receiverSchedule.clear();
                Arrays.fill(plaintextBytes, (byte) 0);
            }
        } catch (IOException | RuntimeException exception) {
            try {
                Files.deleteIfExists(rawPath);
            } catch (IOException ignored) {
                // Retain the original benchmark failure if cleanup is blocked by another process.
            }
            throw exception;
        } finally {
            Arrays.fill(sessionRootKey, (byte) 0);
        }

        writeSummary(summaryPath, runId, iterations, warmup, summaries);
        writeMetadata(metadataPath, runId, iterations, warmup);
        System.out.println("SecureConnect crypto benchmark complete.");
        System.out.println("Raw samples: " + rawPath.toAbsolutePath());
        System.out.println("Summary:     " + summaryPath.toAbsolutePath());
        System.out.println("Run metadata:" + metadataPath.toAbsolutePath());
        System.out.println("Metrics compare an in-memory plaintext byte copy with the client's HKDF-derived AES-256-GCM message-key schedule.");
        System.out.println("This microbenchmark excludes sockets, TLS, login, UI, and disk I/O from timed operations.");
    }

    private static long[][] measureInterleaved(BufferedWriter raw, String runId, int payloadSize,
                                               String[] metricNames, int iterations, int warmup,
                                               List<TimedOperation> operations) throws IOException {
        for (int index = 0; index < warmup; index++) {
            for (TimedOperation operation : operations) operation.run();
        }
        long[][] samples = new long[operations.size()][iterations];
        for (int sample = 0; sample < iterations; sample++) {
            int firstMetric = sample % operations.size();
            for (int offset = 0; offset < operations.size(); offset++) {
                int metric = (firstMetric + offset) % operations.size();
                long processedBytes = metric == 3 ? (long) payloadSize * 2 : payloadSize;
                long start = System.nanoTime();
                operations.get(metric).run();
                long elapsed = System.nanoTime() - start;
                samples[metric][sample] = elapsed;
                double throughput = ((double) processedBytes / (1024.0 * 1024.0))
                        / (elapsed / 1_000_000_000.0);
                raw.write(String.format(Locale.ROOT, "%s,%d,%s,%d,%d,%d,%.6f%n", runId,
                        payloadSize, metricNames[metric], sample + 1, elapsed, processedBytes, throughput));
            }
        }
        raw.flush();
        return samples;
    }

    private static void writeSummary(Path path, String runId, int iterations, int warmup,
                                     List<Summary> summaries) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writer.write("run_id,payload_bytes,metric,sample_count,warmup_iterations,mean_ns,median_ns,p95_ns,std_dev_ns,mean_throughput_mib_per_sec\n");
            for (Summary row : summaries) {
                long processed = "protected_round_trip".equals(row.metric())
                        ? (long) row.payloadBytes() * 2 : row.payloadBytes();
                double throughput = ((double) processed / (1024.0 * 1024.0))
                        / (row.meanNs() / 1_000_000_000.0);
                writer.write(String.format(Locale.ROOT, "%s,%d,%s,%d,%d,%.2f,%.2f,%d,%.2f,%.6f%n",
                        runId, row.payloadBytes(), row.metric(), iterations, warmup, row.meanNs(),
                        row.medianNs(), row.p95Ns(), row.standardDeviationNs(), throughput));
            }
        }
    }

    private static void writeMetadata(Path path, String runId, int iterations, int warmup) throws IOException {
        String metadata = "SecureConnect local crypto microbenchmark\n"
                + "Run ID: " + runId + "\n"
                + "Metadata generated: " + Instant.now() + "\n"
                + "Java version: " + System.getProperty("java.version") + "\n"
                + "Java VM: " + System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version") + "\n"
                + "Operating system: " + System.getProperty("os.name") + " " + System.getProperty("os.version") + "\n"
                + "Architecture: " + System.getProperty("os.arch") + "\n"
                + "Available processors: " + Runtime.getRuntime().availableProcessors() + "\n"
                + "Maximum JVM memory bytes: " + Runtime.getRuntime().maxMemory() + "\n"
                + "Payload sizes bytes: " + Arrays.toString(PAYLOAD_SIZES) + "\n"
                + "Measured iterations per metric and payload: " + iterations + "\n"
                + "Warm-up iterations per metric and payload: " + warmup + "\n"
                + "Sampling order: all metrics warmed together, then interleaved in rotating order per sample.\n"
                + "Protected path: HKDF-derived message key + AES-256-GCM encrypt/decrypt using the project implementation.\n"
                + "Baseline: in-memory plaintext byte-array copy retained in a volatile sink; not a network or server baseline.\n"
                + "Timing: System.nanoTime; no sockets, TLS, authentication, UI, or disk I/O inside timed operations.\n"
                + "Nonce generation and per-operation cipher/key-schedule construction are included in protected timings.\n";
        Files.writeString(path, metadata, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static int parsePositive(String value, String label, int maximum) {
        int parsed = parseInteger(value, label);
        if (parsed < 1 || parsed > maximum) {
            throw new IllegalArgumentException(label + " must be between 1 and " + maximum);
        }
        return parsed;
    }

    private static int parseNonnegative(String value, String label, int maximum) {
        int parsed = parseInteger(value, label);
        if (parsed < 0 || parsed > maximum) {
            throw new IllegalArgumentException(label + " must be between 0 and " + maximum);
        }
        return parsed;
    }

    private static int parseInteger(String value, String label) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(label + " must be a whole number");
        }
    }

    private interface TimedOperation { void run(); }

    private record Summary(int payloadBytes, String metric, int iterations, int warmup,
                           double meanNs, double medianNs, long p95Ns, double standardDeviationNs) {
        static Summary from(int payloadBytes, String metric, int iterations, int warmup, long[] samples) {
            long[] sorted = samples.clone();
            Arrays.sort(sorted);
            double mean = Arrays.stream(samples).average().orElse(0);
            double variance = Arrays.stream(samples).mapToDouble(value -> (value - mean) * (value - mean))
                    .average().orElse(0);
            double median = sorted.length % 2 == 0
                    ? (sorted[sorted.length / 2 - 1] / 2.0 + sorted[sorted.length / 2] / 2.0)
                    : sorted[sorted.length / 2];
            int p95Index = Math.max(0, (int) Math.ceil(sorted.length * 0.95) - 1);
            return new Summary(payloadBytes, metric, iterations, warmup, mean, median,
                    sorted[p95Index], Math.sqrt(variance));
        }
    }
}
