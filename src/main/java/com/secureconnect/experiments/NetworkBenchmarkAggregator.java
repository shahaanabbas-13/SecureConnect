package com.secureconnect.experiments;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** Aggregates independent TLS relay benchmark runs and renders summary charts. */
public final class NetworkBenchmarkAggregator {
    private static final String SUMMARY_HEADER = "run_id,payload_bytes,sample_count,warmup_iterations,mean_ns,median_ns,p95_ns,std_dev_ns,mean_throughput_mib_per_sec,mean_sender_encrypt_encode_ns,mean_sender_socket_write_ns,mean_await_delivery_ns,mean_receiver_decrypt_ns,mean_post_delivery_ack_wait_ns";
    private static final DateTimeFormatter STAMP = DateTimeFormatter
            .ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());
    private static final int[] PHASE_COLUMNS = {9, 10, 11, 12};
    private static final String[] PHASE_NAMES = {"Sender crypto/encode", "TLS socket write", "Wait for delivery", "Receiver decode/decrypt"};
    private static final Color[] PHASE_COLORS = {new Color(49, 177, 141), new Color(77, 145, 218),
            new Color(241, 166, 71), new Color(191, 104, 192)};

    private NetworkBenchmarkAggregator() { }

    public static void run(String[] args) throws IOException {
        if (args.length < 3) {
            throw new IllegalArgumentException("network-benchmark-aggregate syntax: network-benchmark-aggregate <summary-1.csv> <summary-2.csv> [more-summary.csv ...]");
        }
        List<Path> inputs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) inputs.add(Path.of(args[i]).toAbsolutePath().normalize());
        Map<String, Run> runs = new LinkedHashMap<>();
        for (Path path : inputs) {
            Run run = read(path);
            if (runs.putIfAbsent(run.id(), run) != null) throw new IOException("duplicate network benchmark run ID: " + run.id());
        }
        validate(runs);
        Path directory = inputs.getFirst().getParent();
        String id = STAMP.format(Instant.now()) + "-" + UUID.randomUUID().toString().substring(0, 8);
        Path aggregate = directory.resolve("secureconnect-network-aggregate-" + id + ".csv");
        try (BufferedWriter out = Files.newBufferedWriter(aggregate, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            out.write("payload_bytes,run_count,sample_count,warmup_iterations,source_run_ids,mean_of_run_means_ns,between_run_sd_ns,min_run_mean_ns,max_run_mean_ns,mean_of_run_medians_ns,mean_of_run_p95_ns,mean_throughput_mib_per_sec,mean_sender_encrypt_encode_ns,mean_sender_socket_write_ns,mean_await_delivery_ns,mean_receiver_decrypt_ns,mean_post_delivery_ack_wait_ns\n");
            for (int payload : runs.values().iterator().next().rows().keySet()) {
                List<Row> rows = runs.values().stream().map(run -> run.rows().get(payload)).toList();
                double mean = average(rows, Row::mean);
                double variance = rows.stream().mapToDouble(row -> Math.pow(row.mean() - mean, 2)).sum() / (rows.size() - 1);
                double[] values = new double[5 + PHASE_COLUMNS.length];
                values[0] = mean;
                values[1] = Math.sqrt(variance);
                values[2] = rows.stream().mapToDouble(Row::mean).min().orElseThrow();
                values[3] = rows.stream().mapToDouble(Row::mean).max().orElseThrow();
                values[4] = average(rows, Row::median);
                double p95 = average(rows, Row::p95);
                double throughput = average(rows, Row::throughput);
                StringBuilder line = new StringBuilder(String.format(Locale.ROOT,
                        "%d,%d,%d,%d,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.6f",
                        payload, rows.size(), rows.getFirst().samples(), rows.getFirst().warmups(),
                        String.join(";", runs.keySet()), values[0], values[1], values[2], values[3], values[4], p95, throughput));
                for (int phase = 0; phase < PHASE_COLUMNS.length + 1; phase++) {
                    final int index = phase;
                    line.append(',').append(String.format(Locale.ROOT, "%.2f", average(rows, row -> row.phases()[index])));
                }
                out.write(line.append('\n').toString());
            }
        } catch (IOException | RuntimeException exception) {
            Files.deleteIfExists(aggregate);
            throw exception;
        }
        Path latency = directory.resolve("secureconnect-network-aggregate-" + id + "-latency.png");
        Path phases = directory.resolve("secureconnect-network-aggregate-" + id + "-phases.png");
        render(aggregate, latency, false);
        render(aggregate, phases, true);
        System.out.println("Aggregated " + runs.size() + " independent TLS-relay benchmark runs.");
        System.out.println("Between-run standard deviation uses each run's mean latency; runs were not pooled.");
        System.out.println("Aggregate CSV: " + aggregate);
        System.out.println("Latency chart: " + latency);
        System.out.println("Phase chart:   " + phases);
    }

    private static Run read(Path path) throws IOException {
        Map<Integer, Row> rows = new LinkedHashMap<>();
        String id = null;
        Integer samples = null, warmups = null;
        try (BufferedReader in = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            if (!SUMMARY_HEADER.equals(in.readLine())) throw new IOException("not a SecureConnect network benchmark summary: " + path);
            String line;
            int number = 1;
            while ((line = in.readLine()) != null) {
                number++;
                if (line.isBlank()) continue;
                String[] f = line.split(",", -1);
                if (f.length != 14) throw malformed(path, number);
                try {
                    String rowId = f[0]; int payload = Integer.parseInt(f[1]);
                    int rowSamples = Integer.parseInt(f[2]), rowWarmups = Integer.parseInt(f[3]);
                    double[] numeric = new double[10];
                    for (int i = 0; i < numeric.length; i++) numeric[i] = Double.parseDouble(f[4 + i]);
                    if (id == null) id = rowId;
                    if (!id.equals(rowId) || payload <= 0 || rowSamples <= 0 || rowWarmups < 0
                            || !allFinitePositive(numeric)) throw malformed(path, number);
                    if (samples == null) samples = rowSamples;
                    if (warmups == null) warmups = rowWarmups;
                    if (samples != rowSamples || warmups != rowWarmups) throw new IOException("summary contains inconsistent sample settings: " + path);
                    double[] phases = {numeric[5], numeric[6], numeric[7], numeric[8], numeric[9]};
                    if (rows.putIfAbsent(payload, new Row(numeric[0], numeric[1], numeric[2], numeric[3], numeric[4], phases, rowSamples, rowWarmups)) != null)
                        throw new IOException("duplicate payload row: " + path);
                } catch (NumberFormatException exception) { throw malformed(path, number); }
            }
        }
        if (id == null || rows.isEmpty()) throw new IOException("summary contains no data rows: " + path);
        return new Run(id, samples, warmups, rows);
    }

    private static void validate(Map<String, Run> runs) throws IOException {
        Run first = runs.values().iterator().next();
        for (Run run : runs.values()) {
            if (!first.rows().keySet().equals(run.rows().keySet())) throw new IOException("network summaries have different payload sizes");
            if (!first.samples().equals(run.samples()) || !first.warmups().equals(run.warmups()))
                throw new IOException("network summaries use different sample or warm-up settings");
        }
    }

    private static void render(Path csv, Path output, boolean phaseChart) throws IOException {
        List<String[]> data = new ArrayList<>();
        try (BufferedReader in = Files.newBufferedReader(csv, StandardCharsets.UTF_8)) {
            in.readLine(); String line;
            while ((line = in.readLine()) != null) if (!line.isBlank()) data.add(line.split(",", -1));
        }
        int width = 1160, height = 680, left = 100, top = 100, plotW = 800, plotH = 470;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(Color.WHITE); g.fillRect(0, 0, width, height);
            g.setColor(new Color(20, 34, 57)); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 24));
            g.drawString(phaseChart ? "SecureConnect: mean network timing by phase" : "SecureConnect: TLS relay latency across runs", 65, 48);
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); g.setColor(new Color(90, 103, 122));
            g.drawString("Source: " + csv.getFileName() + " | Mean of run summaries; localhost TLS-relay benchmark", 66, 72);
            double max = 0;
            for (String[] row : data) {
                if (phaseChart) for (int col = 12; col <= 15; col++) max = Math.max(max, Double.parseDouble(row[col]));
                else max = Math.max(max, Double.parseDouble(row[5]) + Double.parseDouble(row[6]));
            }
            max = max <= 0 ? 1 : max * 1.15;
            for (int step = 0; step <= 5; step++) {
                int y = top + plotH - step * plotH / 5;
                g.setColor(new Color(224, 230, 238)); g.drawLine(left, y, left + plotW, y);
                g.setColor(new Color(82, 95, 113)); g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
                g.drawString(String.format(Locale.ROOT, "%.1f", max * step / 5.0 / 1_000_000.0), left - 48, y + 4);
            }
            int groupW = plotW / Math.max(data.size(), 1);
            for (int i = 0; i < data.size(); i++) {
                String[] row = data.get(i); int center = left + i * groupW + groupW / 2;
                if (phaseChart) {
                    int barW = 30, gap = 11, total = 4 * barW + 3 * gap, x0 = center - total / 2;
                    for (int p = 0; p < 4; p++) {
                        double value = Double.parseDouble(row[12 + p]);
                        int barH = (int)(value / max * plotH);
                        g.setColor(PHASE_COLORS[p]); g.fillRoundRect(x0 + p * (barW + gap), top + plotH - barH, barW, barH, 4, 4);
                    }
                } else {
                    double value = Double.parseDouble(row[5]); double sd = Double.parseDouble(row[6]);
                    int barH = (int)(value / max * plotH), x = center - 30;
                    g.setColor(new Color(77, 145, 218)); g.fillRoundRect(x, top + plotH - barH, 60, barH, 5, 5);
                    int upper = top + plotH - (int)(Math.min(max, value + sd) / max * plotH);
                    int lower = top + plotH - (int)(Math.max(0, value - sd) / max * plotH);
                    g.setColor(new Color(32, 58, 88)); g.setStroke(new BasicStroke(2)); g.drawLine(center, upper, center, lower); g.drawLine(center - 7, upper, center + 7, upper); g.drawLine(center - 7, lower, center + 7, lower);
                }
                g.setColor(new Color(62, 75, 92)); g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
                g.drawString(formatSize(Integer.parseInt(row[0])), center - 18, top + plotH + 25);
            }
            g.setColor(new Color(42, 54, 71)); g.drawLine(left, top, left, top + plotH); g.drawLine(left, top + plotH, left + plotW, top + plotH);
            g.rotate(-Math.PI / 2); g.drawString("Mean latency (ms)", -(top + plotH / 2 + 35), 28); g.rotate(Math.PI / 2);
            if (phaseChart) for (int p = 0; p < 4; p++) { int y = top + 25 + p * 34; g.setColor(PHASE_COLORS[p]); g.fillRect(935, y - 12, 14, 14); g.setColor(new Color(53,66,84)); g.drawString(PHASE_NAMES[p], 958, y); }
            else { g.setColor(new Color(53,66,84)); g.drawString("Bars: average run mean", 935, top + 25); g.drawString("Whiskers: ± between-run SD", 935, top + 48); }
        } finally { g.dispose(); }
        if (!ImageIO.write(image, "png", output.toFile())) throw new IOException("PNG writer unavailable");
    }

    private static boolean allFinitePositive(double[] values) {
        for (int i = 0; i < values.length; i++) {
            if (!Double.isFinite(values[i]) || (i == 3 ? values[i] < 0 : values[i] <= 0)) return false;
        }
        return true;
    }
    private static IOException malformed(Path path, int line) { return new IOException("malformed network summary at " + path + ":" + line); }
    private static double average(List<Row> rows, Value value) { return rows.stream().mapToDouble(value::get).average().orElseThrow(); }
    private static String formatSize(int bytes) { return bytes >= 1_048_576 ? (bytes / 1_048_576) + " MB" : (bytes / 1_024) + " KB"; }
    private record Run(String id, Integer samples, Integer warmups, Map<Integer, Row> rows) { }
    private record Row(double mean, double median, double p95, double sd, double throughput, double[] phases, int samples, int warmups) { }
    @FunctionalInterface private interface Value { double get(Row row); }
}
