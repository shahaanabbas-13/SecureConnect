package com.secureconnect.experiments;

import javax.imageio.ImageIO;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Creates dependency-free paper-ready latency and throughput PNG charts from a benchmark summary CSV. */
public final class BenchmarkChartRenderer {
    private static final int WIDTH = 1200;
    private static final int HEIGHT = 720;
    private static final String[] METRICS = {
            "plaintext_copy_baseline", "protected_encrypt", "protected_decrypt", "protected_round_trip"
    };
    private static final Color[] COLORS = {
            new Color(77, 145, 218), new Color(49, 177, 141),
            new Color(241, 166, 71), new Color(191, 104, 192)
    };

    private BenchmarkChartRenderer() { }

    public static void render(String[] args) throws IOException {
        if (args.length != 2) {
            throw new IllegalArgumentException("benchmark-chart syntax: benchmark-chart <summary.csv>");
        }
        Path summary = Path.of(args[1]);
        List<BenchmarkRow> rows = readSummary(summary);
        Path parent = summary.toAbsolutePath().getParent();
        String fileName = summary.getFileName().toString();
        String stem = fileName.endsWith("-summary.csv")
                ? fileName.substring(0, fileName.length() - "-summary.csv".length()) : fileName;
        Path latency = parent.resolve(stem + "-latency.png");
        Path throughput = parent.resolve(stem + "-throughput.png");
        renderChart(rows, latency, true, summary.getFileName().toString());
        renderChart(rows, throughput, false, summary.getFileName().toString());
        System.out.println("Latency chart:   " + latency);
        System.out.println("Throughput chart:" + throughput);
    }

    private static List<BenchmarkRow> readSummary(Path summary) throws IOException {
        List<BenchmarkRow> rows = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(summary, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null || !line.startsWith("run_id,payload_bytes,metric,")) {
                throw new IOException("input is not a SecureConnect benchmark summary CSV");
            }
            while ((line = reader.readLine()) != null) {
                String[] fields = line.split(",", -1);
                if (fields.length != 10) continue;
                try {
                    rows.add(new BenchmarkRow(Integer.parseInt(fields[1]), fields[2],
                            Double.parseDouble(fields[5]), Double.parseDouble(fields[9])));
                } catch (NumberFormatException ignored) {
                    // Ignore malformed rows and retain the valid summary entries.
                }
            }
        }
        if (rows.isEmpty()) throw new IOException("summary CSV has no valid benchmark rows");
        return rows;
    }

    private static void renderChart(List<BenchmarkRow> rows, Path output, boolean latency, String sourceName)
            throws IOException {
        Map<Integer, Map<String, Double>> values = new LinkedHashMap<>();
        double min = Double.POSITIVE_INFINITY;
        double max = 0;
        for (BenchmarkRow row : rows) {
            double value = latency ? row.meanNs() : row.meanThroughputMiB();
            values.computeIfAbsent(row.payloadBytes(), ignored -> new LinkedHashMap<>()).put(row.metric(), value);
            min = Math.min(min, value);
            max = Math.max(max, value);
        }
        if (values.isEmpty() || !(max > 0)) throw new IOException("benchmark rows contain no positive values");

        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, WIDTH, HEIGHT);
            g.setColor(new Color(20, 34, 57));
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 25));
            g.drawString(latency ? "SecureConnect: mean operation latency" : "SecureConnect: mean throughput",
                    72, 56);
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
            g.setColor(new Color(90, 103, 122));
            g.drawString("Source: " + sourceName + "  |  Local crypto microbenchmark; values are not network measurements",
                    74, 80);

            int plotLeft = 105, plotTop = 125, plotWidth = 800, plotHeight = 475;
            int plotBottom = plotTop + plotHeight;
            double linearAxisMax = Math.ceil(max / 5.0) * 5.0;
            if (linearAxisMax <= 0) linearAxisMax = max;
            double logAxisMin = Math.pow(10, Math.floor(Math.log10(Math.max(1, min))));
            double logAxisMax = Math.pow(10, Math.ceil(Math.log10(max)));
            if (logAxisMax <= logAxisMin) logAxisMax = logAxisMin * 10;
            if (latency) drawLogAxis(g, plotLeft, plotTop, plotWidth, plotHeight, logAxisMin, logAxisMax);
            else drawLinearAxis(g, plotLeft, plotTop, plotWidth, plotHeight, linearAxisMax);

            List<Integer> sizes = new ArrayList<>(values.keySet());
            int groupWidth = plotWidth / Math.max(1, sizes.size());
            int barWidth = 32;
            int gap = 8;
            int bundleWidth = METRICS.length * barWidth + (METRICS.length - 1) * gap;
            for (int group = 0; group < sizes.size(); group++) {
                int payload = sizes.get(group);
                int groupLeft = plotLeft + group * groupWidth + (groupWidth - bundleWidth) / 2;
                Map<String, Double> metricValues = values.get(payload);
                for (int metric = 0; metric < METRICS.length; metric++) {
                    Double value = metricValues.get(METRICS[metric]);
                    if (value == null || value <= 0) continue;
                    int barX = groupLeft + metric * (barWidth + gap);
                    int y = latency ? logY(value, logAxisMin, logAxisMax, plotTop, plotHeight)
                            : linearY(value, linearAxisMax, plotTop, plotHeight);
                    g.setColor(COLORS[metric]);
                    g.fillRoundRect(barX, y, barWidth, Math.max(1, plotBottom - y), 5, 5);
                }
                g.setColor(new Color(62, 75, 92));
                g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
                g.drawString(formatSize(payload), plotLeft + group * groupWidth + groupWidth / 2 - 18,
                        plotBottom + 27);
            }

            g.setColor(new Color(42, 54, 71));
            g.setStroke(new BasicStroke(1.4f));
            g.drawLine(plotLeft, plotTop, plotLeft, plotBottom);
            g.drawLine(plotLeft, plotBottom, plotLeft + plotWidth, plotBottom);
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
            g.drawString(latency ? "Payload size" : "Payload size", plotLeft + plotWidth / 2 - 35,
                    plotBottom + 58);
            g.rotate(-Math.PI / 2);
            g.drawString(latency ? "Mean latency (ns, logarithmic scale)" : "Mean throughput (MiB/s)",
                    -(plotTop + plotHeight / 2 + 80), 28);
            g.rotate(Math.PI / 2);
            drawLegend(g, plotLeft + plotWidth + 45, plotTop + 35);
        } finally {
            g.dispose();
        }
        if (!ImageIO.write(image, "png", output.toFile())) {
            throw new IOException("No PNG image writer is available.");
        }
    }

    private static void drawLogAxis(Graphics2D g, int left, int top, int width, int height,
                                    double minValue, double maxValue) {
        int minExp = (int) Math.round(Math.log10(minValue));
        int maxExp = (int) Math.round(Math.log10(maxValue));
        for (int exponent = minExp; exponent <= maxExp; exponent++) {
            double value = Math.pow(10, exponent);
            int y = logY(value, minValue, maxValue, top, height);
            g.setColor(new Color(224, 230, 238));
            g.drawLine(left, y, left + width, y);
            g.setColor(new Color(82, 95, 113));
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            g.drawString("10^" + exponent, left - 48, y + 4);
        }
    }

    private static void drawLinearAxis(Graphics2D g, int left, int top, int width, int height, double max) {
        double axisMax = max;
        if (axisMax <= 0) axisMax = max;
        for (int step = 0; step <= 5; step++) {
            double value = axisMax * step / 5.0;
            int y = linearY(value, axisMax, top, height);
            g.setColor(new Color(224, 230, 238));
            g.drawLine(left, y, left + width, y);
            g.setColor(new Color(82, 95, 113));
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
            g.drawString(String.format(Locale.ROOT, "%.1f", value), left - 42, y + 4);
        }
    }

    private static int logY(double value, double minValue, double maxValue, int top, int height) {
        double low = Math.log10(Math.max(1, minValue));
        double high = Math.log10(Math.max(minValue * 10, maxValue));
        double ratio = (Math.log10(Math.max(1, value)) - low) / (high - low);
        return top + height - (int) Math.round(Math.max(0, Math.min(1, ratio)) * height);
    }

    private static int linearY(double value, double max, int top, int height) {
        double ratio = value / max;
        return top + height - (int) Math.round(Math.max(0, Math.min(1, ratio)) * height);
    }

    private static void drawLegend(Graphics2D g, int x, int y) {
        g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        for (int index = 0; index < METRICS.length; index++) {
            g.setColor(COLORS[index]);
            g.fillRoundRect(x, y + index * 32, 15, 15, 3, 3);
            g.setColor(new Color(53, 66, 84));
            g.drawString(METRICS[index].replace('_', ' '), x + 24, y + 12 + index * 32);
        }
    }

    private static String formatSize(int bytes) {
        if (bytes >= 1_048_576) return (bytes / 1_048_576) + " MB";
        return (bytes / 1_024) + " KB";
    }

    private record BenchmarkRow(int payloadBytes, String metric, double meanNs, double meanThroughputMiB) { }
}
