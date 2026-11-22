package com.secureconnect.experiments;

import com.secureconnect.crypto.MessageKeySchedule;
import com.secureconnect.security.IncomingSequenceGuard;

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
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/** Reproducible local trials of the message-integrity and sequence controls used by the client. */
public final class SecurityEvaluationRunner {
    private static final Path DEFAULT_OUTPUT = Path.of("experiments", "results");
    private static final DateTimeFormatter STAMP = DateTimeFormatter
            .ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());
    private static final SecureRandom RANDOM = new SecureRandom();

    private SecurityEvaluationRunner() { }

    public static void run(String[] args) throws IOException {
        int trials = args.length >= 2 ? parseTrials(args[1]) : 100;
        Path outputDirectory = args.length >= 3 ? Path.of(args[2]) : DEFAULT_OUTPUT;
        if (args.length > 3) {
            throw new IllegalArgumentException("security-evaluation syntax: security-evaluation [trials] [output-directory]");
        }
        Files.createDirectories(outputDirectory);
        String runId = STAMP.format(Instant.now()) + "-" + UUID.randomUUID().toString().substring(0, 8);
        Path csvPath = outputDirectory.resolve("secureconnect-security-" + runId + ".csv");
        List<Result> results = new ArrayList<>();
        String[] attacks = {"tamper", "replay", "out_of_order", "wrong_key_version"};
        int[] rejected = new int[attacks.length];
        byte[] rootKey = new byte[32];

        try {
            for (int trial = 0; trial < trials; trial++) {
                RANDOM.nextBytes(rootKey);
                MessageKeySchedule sender = new MessageKeySchedule(rootKey, "EvalAlice", "EvalBob");
                MessageKeySchedule receiver = new MessageKeySchedule(rootKey, "EvalBob", "EvalAlice");
                String validEnvelope = sender.encrypt("evaluation-message-" + trial, 1);

                if (rejectsTamper(receiver, tamper(validEnvelope))) rejected[0]++;

                IncomingSequenceGuard replayGuard = new IncomingSequenceGuard();
                String firstMessage = receiver.decrypt(validEnvelope, "EvalAlice", 1, 0);
                if (!("evaluation-message-" + trial).equals(firstMessage) || !replayGuard.accept(1)) {
                    throw new IllegalStateException("valid control message was not accepted");
                }
                if (!replayGuard.accept(1)) rejected[1]++;

                IncomingSequenceGuard orderGuard = new IncomingSequenceGuard();
                boolean firstAccepted = orderGuard.accept(1);
                boolean outOfOrderRejected = !orderGuard.accept(3);
                if (firstAccepted && outOfOrderRejected) rejected[2]++;

                try {
                    receiver.decrypt(validEnvelope, "EvalAlice", 1, 1);
                } catch (SecurityException | IllegalArgumentException expected) {
                    rejected[3]++;
                }
                sender.clear();
                receiver.clear();
            }

            try (BufferedWriter writer = Files.newBufferedWriter(csvPath, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                writer.write("run_id,attack,trials,rejected,detection_rate_percent\n");
                for (int i = 0; i < attacks.length; i++) {
                    double rate = 100.0 * rejected[i] / trials;
                    writer.write(String.format(Locale.ROOT, "%s,%s,%d,%d,%.2f%n",
                            runId, attacks[i], trials, rejected[i], rate));
                    results.add(new Result(attacks[i], rejected[i], rate));
                }
            }
        } finally {
            java.util.Arrays.fill(rootKey, (byte) 0);
        }

        System.out.println("SecureConnect local security-control evaluation complete.");
        System.out.println("Trials per attack: " + trials);
        for (Result result : results) {
            System.out.printf(Locale.ROOT, "%-20s %d/%d rejected (%.2f%%)%n",
                    result.attack(), result.rejected(), trials, result.detectionRate());
        }
        System.out.println("CSV results: " + csvPath.toAbsolutePath());
        System.out.println("These are local message-layer control trials, not network attack success rates.");
    }

    private static boolean rejectsTamper(MessageKeySchedule receiver, String changedEnvelope) {
        try {
            receiver.decrypt(changedEnvelope, "EvalAlice", 1, 0);
            return false;
        } catch (SecurityException | IllegalArgumentException expected) {
            return true;
        }
    }

    private static String tamper(String encoded) {
        byte[] bytes = Base64.getDecoder().decode(encoded.substring("SC1.".length()));
        int firstCiphertextByte = 12;
        if (bytes.length <= firstCiphertextByte) throw new IllegalStateException("unexpected test envelope size");
        bytes[firstCiphertextByte] ^= 1;
        return "SC1." + Base64.getEncoder().encodeToString(bytes);
    }

    private static int parseTrials(String value) {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1 || parsed > 100_000) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("trials must be between 1 and 100000");
        }
    }

    private record Result(String attack, int rejected, double detectionRate) { }
}
