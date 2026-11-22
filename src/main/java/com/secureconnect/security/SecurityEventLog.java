package com.secureconnect.security;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/** Shared append-only audit log for relay, clients, and the local attack simulator. */
public final class SecurityEventLog {
    private static final Path DEFAULT_PATH = Path.of("data", "security-events.tsv");
    private static final int MAX_DASHBOARD_EVENTS = 5_000;
    private static final Object LOCAL_WRITE_LOCK = new Object();

    private SecurityEventLog() { }

    public static void record(String type, Severity severity, String actor, String summary) {
        if (type == null || !type.matches("[A-Z0-9_]{2,48}")) return;
        SecurityEvent event = new SecurityEvent(UUID.randomUUID().toString(), Instant.now(), type,
                severity == null ? Severity.INFO : severity,
                actor == null ? "system" : actor,
                summary == null ? "" : summary);
        Path path = logPath();
        Path parent = path.toAbsolutePath().getParent();
        String line = event.timestamp() + "\t" + event.severity().name() + "\t" + event.type()
                + "\t" + encode(event.actor()) + "\t" + encode(event.summary()) + System.lineSeparator();
        synchronized (LOCAL_WRITE_LOCK) {
            try {
                if (parent != null) Files.createDirectories(parent);
                try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                     FileLock ignored = channel.lock()) {
                    ByteBuffer bytes = StandardCharsets.UTF_8.encode(line);
                    while (bytes.hasRemaining()) channel.write(bytes);
                }
            } catch (IOException | RuntimeException exception) {
                System.err.println("Could not append SecureConnect audit event to " + path + ".");
            }
        }
    }

    public static List<SecurityEvent> readRecent() throws IOException {
        Path path = logPath();
        if (!Files.exists(path)) return List.of();
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        int start = Math.max(0, lines.size() - MAX_DASHBOARD_EVENTS);
        List<SecurityEvent> events = new ArrayList<>(lines.size() - start);
        for (int index = start; index < lines.size(); index++) {
            String[] fields = lines.get(index).split("\\t", 5);
            if (fields.length != 5) continue;
            try {
                events.add(new SecurityEvent(UUID.randomUUID().toString(), Instant.parse(fields[0]),
                        fields[2], Severity.valueOf(fields[1]), decode(fields[3]), decode(fields[4])));
            } catch (IllegalArgumentException ignored) {
                // Ignore a partially written or malformed audit row and continue with valid rows.
            }
        }
        return List.copyOf(events);
    }

    public static Path logPath() {
        String configured = System.getenv("SECURECONNECT_EVENT_LOG");
        return configured == null || configured.isBlank() ? DEFAULT_PATH : Path.of(configured);
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    public enum Severity { INFO, WARNING, ALERT }

    public record SecurityEvent(String id, Instant timestamp, String type, Severity severity,
                                String actor, String summary) { }
}
