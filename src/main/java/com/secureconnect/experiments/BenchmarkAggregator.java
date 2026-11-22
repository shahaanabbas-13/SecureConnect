package com.secureconnect.experiments;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** Aggregates per-run summary statistics without pooling raw samples from separate JVM runs. */
public final class BenchmarkAggregator {
    private static final String HEADER = "run_id,payload_bytes,metric,sample_count,warmup_iterations,mean_ns,median_ns,p95_ns,std_dev_ns,mean_throughput_mib_per_sec";
    private static final DateTimeFormatter STAMP = DateTimeFormatter
            .ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());

    private BenchmarkAggregator() { }

    public static void run(String[] args) throws IOException {
        if (args.length < 3) {
            throw new IllegalArgumentException("benchmark-aggregate syntax: benchmark-aggregate <summary-1.csv> <summary-2.csv> [more-summary.csv ...]");
        }

        List<Path> inputs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) inputs.add(Path.of(args[i]).toAbsolutePath().normalize());
        Map<String, RunData> runs = new LinkedHashMap<>();
        for (Path input : inputs) {
            RunData data = readRun(input);
            if (runs.putIfAbsent(data.runId(), data) != null) {
                throw new IOException("duplicate benchmark run ID in inputs: " + data.runId());
            }
        }
        validateRuns(runs);

        Path outputDirectory = inputs.getFirst().getParent();
        String outputName = "secureconnect-aggregate-" + STAMP.format(Instant.now()) + "-"
                + UUID.randomUUID().toString().substring(0, 8) + ".csv";
        Path output = outputDirectory.resolve(outputName);
        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            writer.write("payload_bytes,metric,run_count,source_run_ids,mean_of_run_means_ns,between_run_sd_ns,min_run_mean_ns,max_run_mean_ns,mean_of_run_medians_ns,mean_of_run_p95_ns,mean_throughput_mib_per_sec\n");
            for (MetricKey key : sortedKeys(runs.values().iterator().next().rows().keySet())) {
                List<Row> rows = runs.values().stream().map(run -> run.rows().get(key)).toList();
                double mean = rows.stream().mapToDouble(Row::meanNs).average().orElseThrow();
                double variance = rows.stream().mapToDouble(row -> (row.meanNs() - mean) * (row.meanNs() - mean))
                        .sum() / (rows.size() - 1);
                double min = rows.stream().mapToDouble(Row::meanNs).min().orElseThrow();
                double max = rows.stream().mapToDouble(Row::meanNs).max().orElseThrow();
                double meanMedian = rows.stream().mapToDouble(Row::medianNs).average().orElseThrow();
                double meanP95 = rows.stream().mapToDouble(Row::p95Ns).average().orElseThrow();
                double meanThroughput = rows.stream().mapToDouble(Row::throughput).average().orElseThrow();
                String runIds = String.join(";", runs.keySet());
                writer.write(String.format(Locale.ROOT, "%d,%s,%d,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.6f%n",
                        key.payloadBytes(), key.metric(), rows.size(), runIds, mean, Math.sqrt(variance),
                        min, max, meanMedian, meanP95, meanThroughput));
            }
        } catch (IOException | RuntimeException exception) {
            Files.deleteIfExists(output);
            throw exception;
        }

        System.out.println("Aggregated " + runs.size() + " independent benchmark summaries.");
        System.out.println("Between-run standard deviation is computed from each run's mean latency.");
        System.out.println("Aggregate CSV: " + output);
    }

    private static RunData readRun(Path path) throws IOException {
        Map<MetricKey, Row> rows = new LinkedHashMap<>();
        String runId = null;
        Integer sampleCount = null;
        Integer warmup = null;
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            if (!HEADER.equals(reader.readLine())) {
                throw new IOException("not a SecureConnect benchmark summary CSV: " + path);
            }
            String line;
            int lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank()) continue;
                String[] fields = line.split(",", -1);
                if (fields.length != 10) throw malformed(path, lineNumber);
                try {
                    String rowRunId = fields[0];
                    int payload = Integer.parseInt(fields[1]);
                    String metric = fields[2];
                    int samples = Integer.parseInt(fields[3]);
                    int warmups = Integer.parseInt(fields[4]);
                    Row row = new Row(Double.parseDouble(fields[5]), Double.parseDouble(fields[6]),
                            Double.parseDouble(fields[7]), Double.parseDouble(fields[8]),
                            Double.parseDouble(fields[9]), samples, warmups);
                    if (rowRunId.isBlank() || payload <= 0 || samples <= 0 || warmups < 0
                            || !row.allFiniteAndPositive()) throw malformed(path, lineNumber);
                    if (runId == null) runId = rowRunId;
                    if (!runId.equals(rowRunId)) throw new IOException("summary contains multiple run IDs: " + path);
                    if (sampleCount == null) sampleCount = samples;
                    if (warmup == null) warmup = warmups;
                    if (sampleCount != samples || warmup != warmups) {
                        throw new IOException("summary contains inconsistent sample settings: " + path);
                    }
                    MetricKey key = new MetricKey(payload, metric);
                    if (rows.putIfAbsent(key, row) != null) {
                        throw new IOException("duplicate payload/metric row in summary: " + path);
                    }
                } catch (NumberFormatException exception) {
                    throw malformed(path, lineNumber);
                }
            }
        }
        if (runId == null || rows.isEmpty()) throw new IOException("summary has no result rows: " + path);
        return new RunData(runId, sampleCount, warmup, rows);
    }

    private static void validateRuns(Map<String, RunData> runs) throws IOException {
        RunData first = runs.values().iterator().next();
        for (RunData run : runs.values()) {
            if (!first.rows().keySet().equals(run.rows().keySet())) {
                throw new IOException("input summaries do not contain the same payload/metric rows");
            }
            if (!first.sampleCount().equals(run.sampleCount()) || !first.warmup().equals(run.warmup())) {
                throw new IOException("input summaries use different iteration or warm-up settings");
            }
        }
    }

    private static List<MetricKey> sortedKeys(Iterable<MetricKey> keys) {
        List<MetricKey> sorted = new ArrayList<>();
        keys.forEach(sorted::add);
        sorted.sort(Comparator.comparingInt(MetricKey::payloadBytes).thenComparing(MetricKey::metric));
        return sorted;
    }

    private static IOException malformed(Path path, int line) {
        return new IOException("malformed benchmark summary at " + path + ":" + line);
    }

    private record MetricKey(int payloadBytes, String metric) { }
    private record Row(double meanNs, double medianNs, double p95Ns, double sdNs,
                       double throughput, int samples, int warmups) {
        boolean allFiniteAndPositive() {
            return Double.isFinite(meanNs) && meanNs > 0 && Double.isFinite(medianNs) && medianNs > 0
                    && Double.isFinite(p95Ns) && p95Ns > 0 && Double.isFinite(sdNs) && sdNs >= 0
                    && Double.isFinite(throughput) && throughput > 0;
        }
    }
    private record RunData(String runId, Integer sampleCount, Integer warmup,
                           Map<MetricKey, Row> rows) { }
}
