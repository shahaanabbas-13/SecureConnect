package com.secureconnect.security;

import com.secureconnect.security.SecurityEventLog.SecurityEvent;
import com.secureconnect.security.SecurityEventLog.Severity;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.plaf.basic.BasicButtonUI;
import javax.swing.plaf.basic.BasicComboBoxUI;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.RenderingHints;
import java.awt.BasicStroke;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;

/** Desktop dashboard for the local SecureConnect security audit log. */
public final class SecurityDashboard {
    private static final Color BACKGROUND = new Color(241, 246, 244);
    private static final Color PANEL = Color.WHITE;
    private static final Color ACCENT = new Color(0, 132, 111);
    private static final Color TEXT = new Color(30, 49, 52);
    private static final Color MUTED = new Color(91, 111, 114);
    private static final Color BORDER = new Color(213, 225, 221);
    private static final Color SOFT_ROW = new Color(246, 250, 248);
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final JFrame frame = new JFrame("SecureConnect | Security Dashboard");
    private final EventTableModel model = new EventTableModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<EventTableModel> sorter = new TableRowSorter<>(model);
    private final JLabel totalValue = new JLabel("0");
    private final JLabel attacksValue = new JLabel("0");
    private final JLabel rejectedValue = new JLabel("0");
    private final JLabel sessionsValue = new JLabel("0");
    private final JLabel status = new JLabel("Starting audit log reader…");
    private final JTextField search = new JTextField(20);
    private final JComboBox<String> severityFilter = new JComboBox<>(
            new String[]{"All severities", "INFO", "WARNING", "CRITICAL"});
    private final JComboBox<String> categoryFilter = new JComboBox<>(new String[]{
            "All categories", "Authentication", "Encryption", "Sessions", "Attacks", "Network"});
    private final JLabel tableStatus = new JLabel("All events");
    private final JLabel detailTitle = new JLabel("Event inspector");
    private final JTextArea eventDetails = new JTextArea();
    private final JPanel detailPanel = new JPanel(new BorderLayout(0, 10));
    private final ActivityChart activityChart = new ActivityChart();
    private final SeverityChart severityChart = new SeverityChart();
    private List<SecurityEvent> allEvents = List.of();
    private List<SecurityEvent> filteredEvents = List.of();
    private String selectedEventId;
    private boolean refreshInProgress;
    private boolean paused;
    private final Timer refreshTimer = new Timer(2_000, event -> refresh());

    private SecurityDashboard() {
        configureLookAndFeel();
        buildWindow();
        refreshTimer.start();
        refresh();
    }

    public static void launch() {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            System.err.println("The SecureConnect dashboard needs a desktop session.");
            return;
        }
        javax.swing.SwingUtilities.invokeLater(SecurityDashboard::new);
    }

    private static void configureLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Swing's default look and feel is sufficient for the local dashboard.
        }
    }

    private void buildWindow() {
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setMinimumSize(new Dimension(1080, 700));
        frame.setSize(1480, 900);
        frame.setLocationByPlatform(true);
        frame.getContentPane().setBackground(BACKGROUND);

        JPanel root = new JPanel(new BorderLayout(0, 18));
        root.setBackground(BACKGROUND);
        root.setBorder(new EmptyBorder(24, 28, 18, 28));
        root.add(buildHeader(), BorderLayout.NORTH);
        root.add(buildEventsPanel(), BorderLayout.CENTER);
        root.add(buildFooter(), BorderLayout.SOUTH);
        frame.setContentPane(root);
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent event) { refreshTimer.stop(); }
        });
        frame.setVisible(true);
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel(new BorderLayout(0, 18));
        header.setOpaque(false);

        JPanel titleBlock = new JPanel(new BorderLayout(0, 4));
        titleBlock.setOpaque(false);
        JLabel eyebrow = new JLabel("SECURECONNECT  /  LOCAL MONITOR");
        eyebrow.setForeground(ACCENT);
        eyebrow.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        JLabel title = new JLabel("Security events");
        title.setForeground(TEXT);
        title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 28));
        JLabel subtitle = new JLabel("Authentication, session controls, and controlled attack activity");
        subtitle.setForeground(MUTED);
        subtitle.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        JPanel heading = new JPanel(new GridLayout(3, 1, 0, 3));
        heading.setOpaque(false);
        heading.add(eyebrow);
        heading.add(title);
        heading.add(subtitle);
        titleBlock.add(heading, BorderLayout.WEST);

        JButton pauseButton = new JButton("Ⅱ  Pause");
        styleButton(pauseButton);
        pauseButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        pauseButton.setPreferredSize(new Dimension(104, 34));
        pauseButton.setBorder(new EmptyBorder(5, 9, 5, 9));
        pauseButton.addActionListener(event -> {
            paused = !paused;
            pauseButton.setText(paused ? "▶  Resume" : "Ⅱ  Pause");
            status.setText(paused ? "Updates paused" : "Watching " + SecurityEventLog.logPath());
        });
        JPanel pauseTools = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 0, 0));
        pauseTools.setOpaque(false); pauseTools.add(pauseButton);
        titleBlock.add(pauseTools, BorderLayout.EAST);
        header.add(titleBlock, BorderLayout.NORTH);

        JPanel cards = new JPanel(new GridLayout(1, 4, 12, 0));
        cards.setOpaque(false);
        cards.add(metricCard("◉  EVENTS LOADED", totalValue, "Latest 5,000 audit entries"));
        cards.add(metricCard("⚑  ATTACK ACTIVITY", attacksValue, "Controlled lab actions"));
        cards.add(metricCard("✓  REJECTIONS", rejectedValue, "Login, replay, and integrity"));
        cards.add(metricCard("↔  SESSION EVENTS", sessionsValue, "Open, close, and expiry"));
        header.add(cards, BorderLayout.SOUTH);
        return header;
    }

    private JPanel metricCard(String label, JLabel value, String caption) {
        JPanel card = new JPanel(new BorderLayout(0, 8));
        card.setBackground(PANEL);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER), new EmptyBorder(14, 16, 14, 16)));
        JLabel name = new JLabel(label);
        name.setForeground(MUTED);
        name.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        value.setForeground(TEXT);
        value.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 26));
        JLabel note = new JLabel(caption);
        note.setForeground(MUTED);
        note.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        card.add(name, BorderLayout.NORTH);
        card.add(value, BorderLayout.CENTER);
        card.add(note, BorderLayout.SOUTH);
        return card;
    }

    private JPanel buildEventsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBackground(PANEL);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER), new EmptyBorder(16, 16, 16, 16)));

        JPanel tools = new JPanel(new BorderLayout(12, 0));
        tools.setOpaque(false);
        JLabel label = new JLabel("Audit trail");
        label.setForeground(TEXT);
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        tools.add(label, BorderLayout.WEST);
        JPanel filters = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 8, 0));
        filters.setOpaque(false);
        styleInput(search);
        search.setToolTipText("Search event type, actor, details, or timestamp");
        search.setPreferredSize(new Dimension(190, 34));
        styleSeverityFilter();
        styleFilter(categoryFilter);
        filters.add(search);
        filters.add(severityFilter);
        filters.add(categoryFilter);
        tools.add(filters, BorderLayout.EAST);
        JPanel leftContent = new JPanel(new BorderLayout(0, 8));
        leftContent.setOpaque(false);
        JPanel charts = new JPanel(new GridLayout(1, 2, 10, 0));
        charts.setOpaque(false);
        styleChart(activityChart, "ACTIVITY • LAST 24 HOURS");
        styleChart(severityChart, "SEVERITY DISTRIBUTION");
        charts.add(activityChart); charts.add(severityChart);
        leftContent.add(charts, BorderLayout.NORTH);

        table.setRowSorter(sorter);
        table.setFillsViewportHeight(true);
        table.setRowHeight(34);
        table.setShowVerticalLines(false);
        table.setGridColor(BORDER);
        table.setBackground(PANEL);
        table.setForeground(TEXT);
        table.setSelectionBackground(new Color(211, 238, 229));
        table.setSelectionForeground(TEXT);
        table.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        table.getTableHeader().setBackground(new Color(229, 240, 236));
        table.getTableHeader().setForeground(MUTED);
        table.getTableHeader().setOpaque(true);
        table.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        table.getTableHeader().setPreferredSize(new Dimension(0, 34));
        table.getColumnModel().getColumn(0).setPreferredWidth(145);
        table.getColumnModel().getColumn(1).setPreferredWidth(88);
        table.getColumnModel().getColumn(2).setPreferredWidth(170);
        table.getColumnModel().getColumn(3).setPreferredWidth(105);
        table.getColumnModel().getColumn(4).setPreferredWidth(390);
        table.setDefaultRenderer(Object.class, new EventCellRenderer());
        JScrollPane scroll = new JScrollPane(table);
        scroll.getViewport().setBackground(PANEL);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER));
        leftContent.add(scroll, BorderLayout.CENTER);
        JPanel tableFooter = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 8, 2));
        tableFooter.setOpaque(false);
        tableStatus.setForeground(MUTED); tableStatus.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        tableFooter.add(tableStatus);
        leftContent.add(tableFooter, BorderLayout.SOUTH);

        detailPanel.setBackground(new Color(248, 251, 249));
        detailPanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER), new EmptyBorder(12, 12, 12, 12)));
        detailTitle.setForeground(TEXT); detailTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        JLabel detailHint = new JLabel("Select a row to inspect its recorded fields.");
        detailHint.setForeground(MUTED); detailHint.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
        JPanel detailHeading = new JPanel(new BorderLayout(0, 5)); detailHeading.setOpaque(false);
        detailHeading.add(detailTitle, BorderLayout.NORTH); detailHeading.add(detailHint, BorderLayout.SOUTH);
        detailPanel.add(detailHeading, BorderLayout.NORTH);
        eventDetails.setEditable(false); eventDetails.setLineWrap(true); eventDetails.setWrapStyleWord(true);
        eventDetails.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11)); eventDetails.setForeground(TEXT);
        eventDetails.setBackground(new Color(248, 251, 249)); eventDetails.setBorder(new EmptyBorder(3, 0, 3, 0));
        eventDetails.setText("Choose any audit row.\n\nThis panel shows the entry ID, time, severity, category, actor, event type, and details.\n\nSession and message IDs are shown only when the audit record contains them.");
        detailPanel.add(new JScrollPane(eventDetails), BorderLayout.CENTER);
        detailPanel.setPreferredSize(new Dimension(275, 0));
        table.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && table.getSelectedRow() >= 0) {
                int row = table.convertRowIndexToModel(table.getSelectedRow());
                if (row >= 0 && row < model.getRowCount()) showEventDetails(model.eventAt(row));
            }
        });
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftContent, detailPanel);
        split.setResizeWeight(0.79); split.setContinuousLayout(true); split.setBorder(null);
        panel.add(tools, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { applyFilters(); }
            @Override public void removeUpdate(DocumentEvent event) { applyFilters(); }
            @Override public void changedUpdate(DocumentEvent event) { applyFilters(); }
        });
        severityFilter.addActionListener(event -> applyFilters());
        categoryFilter.addActionListener(event -> applyFilters());
        return panel;
    }

    private void styleChart(JPanel chart, String title) {
        chart.setBackground(PANEL); chart.setOpaque(true);
        chart.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER), new EmptyBorder(8, 10, 8, 10)));
        chart.setPreferredSize(new Dimension(0, 145)); chart.setToolTipText(title);
    }

    private void styleFilter(JComboBox<String> filter) {
        filter.setUI(new BasicComboBoxUI()); filter.setOpaque(true); filter.setBackground(Color.WHITE);
        filter.setForeground(TEXT); filter.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        filter.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER), new EmptyBorder(4, 6, 4, 6)));
        filter.setRenderer((list, value, index, selected, focus) -> {
            JLabel item = new JLabel(String.valueOf(value)); item.setOpaque(true); item.setFont(filter.getFont());
            item.setBorder(new EmptyBorder(5, 7, 5, 7)); item.setForeground(TEXT);
            item.setBackground(selected ? new Color(221, 241, 234) : Color.WHITE); return item;
        });
    }

    private static void styleOutlineButton(JButton button) {
        button.setUI(new BasicButtonUI()); button.setOpaque(true); button.setContentAreaFilled(true);
        button.setBackground(Color.WHITE); button.setForeground(ACCENT); button.setFocusPainted(false);
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        button.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(BORDER), new EmptyBorder(6, 9, 6, 9)));
    }

    private void applyFilters() {
        String needle = search.getText().trim().toLowerCase(Locale.ROOT);
        String severity = (String) severityFilter.getSelectedItem();
        String category = (String) categoryFilter.getSelectedItem();
        filteredEvents = allEvents.stream().filter(event -> {
            String shownSeverity = event.severity() == Severity.ALERT ? "CRITICAL" : event.severity().name();
            boolean severityMatch = "All severities".equals(severity) || shownSeverity.equals(severity);
            boolean categoryMatch = "All categories".equals(category) || categoryFor(event).equals(category);
            String searchable = (TIME_FORMAT.format(event.timestamp()) + " " + shownSeverity + " "
                    + event.type() + " " + event.actor() + " " + event.summary()).toLowerCase(Locale.ROOT);
            return severityMatch && categoryMatch && (needle.isEmpty() || searchable.contains(needle));
        }).toList();
        showFilteredEvents();
        activityChart.repaint(); severityChart.repaint();
    }

    private void showFilteredEvents() {
        model.setEvents(filteredEvents);
        tableStatus.setText("Showing all " + filteredEvents.size() + " matching events • click a column to sort");
        table.clearSelection();
        if (selectedEventId != null) {
            int modelIndex = -1;
            for (int i = 0; i < model.getRowCount(); i++) {
                if (selectedEventId.equals(model.eventAt(i).id())) { modelIndex = i; break; }
            }
            if (modelIndex >= 0) {
                for (int viewIndex = 0; viewIndex < table.getRowCount(); viewIndex++) {
                    if (table.convertRowIndexToModel(viewIndex) == modelIndex) {
                        table.setRowSelectionInterval(viewIndex, viewIndex);
                        break;
                    }
                }
            } else {
                selectedEventId = null;
                showInspectorPlaceholder();
            }
        }
    }

    private void showEventDetails(SecurityEvent event) {
        selectedEventId = event.id();
        detailTitle.setText(event.type().replace('_', ' '));
        String severity = event.severity() == Severity.ALERT ? "CRITICAL (logged as ALERT)" : event.severity().name();
        eventDetails.setText("TIME\n" + TIME_FORMAT.format(event.timestamp())
                + "\n\nAUDIT ENTRY ID\n" + event.id()
                + "\n\nSEVERITY\n" + severity
                + "\n\nCATEGORY\n" + categoryFor(event)
                + "\n\nACTOR\n" + event.actor()
                + "\n\nEVENT\n" + event.type()
                + "\n\nDETAILS\n" + event.summary()
                + "\n\nSESSION / MESSAGE\nNot recorded in this audit entry.");
        eventDetails.setCaretPosition(0);
    }

    private void showInspectorPlaceholder() {
        detailTitle.setText("Event inspector");
        eventDetails.setText("Choose any audit row.\n\nThis panel shows the entry ID, time, severity, category, actor, event type, and details.\n\nSession and message IDs are shown only when the audit record contains them.");
        eventDetails.setCaretPosition(0);
    }

    private static String categoryFor(SecurityEvent event) {
        String type = event.type();
        if (type.startsWith("AUTH_") || type.startsWith("LOGIN_") || type.startsWith("ACCOUNT_")) return "Authentication";
        if (type.startsWith("SESSION_")) return "Sessions";
        if (type.startsWith("ATTACK_")) return "Attacks";
        if (type.contains("INTEGRITY") || type.contains("REPLAY") || type.contains("KEY")
                || type.contains("CRYPTO") || type.contains("TAMPER") || type.contains("SIGNATURE")) return "Encryption";
        if (type.contains("MESSAGE_") || type.startsWith("TLS_") || type.startsWith("NETWORK_")) return "Network";
        return "Network";
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setOpaque(false);
        status.setForeground(MUTED);
        status.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        footer.add(status, BorderLayout.WEST);
        JLabel privacy = new JLabel("Local only • message contents and passwords are never recorded");
        privacy.setForeground(MUTED);
        privacy.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        footer.add(privacy, BorderLayout.EAST);
        return footer;
    }

    private void refresh() {
        if (paused || refreshInProgress) return;
        refreshInProgress = true;
        new SwingWorker<List<SecurityEvent>, Void>() {
            @Override protected List<SecurityEvent> doInBackground() throws IOException {
                return SecurityEventLog.readRecent();
            }

            @Override protected void done() {
                refreshInProgress = false;
                try {
                    List<SecurityEvent> events = get();
                    allEvents = events;
                    updateMetrics(events);
                    applyFilters();
                    status.setText("Watching " + SecurityEventLog.logPath() + "  •  refreshed "
                            + TIME_FORMAT.format(java.time.Instant.now()));
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    status.setText("Audit refresh interrupted");
                } catch (ExecutionException exception) {
                    status.setText("Could not read audit log: " + exception.getCause().getMessage());
                }
            }
        }.execute();
    }

    private void updateMetrics(List<SecurityEvent> events) {
        totalValue.setText(Integer.toString(events.size()));
        attacksValue.setText(Long.toString(events.stream().filter(e -> e.type().startsWith("ATTACK_")).count()));
        rejectedValue.setText(Long.toString(events.stream().filter(SecurityDashboard::isRejection).count()));
        sessionsValue.setText(Long.toString(events.stream().filter(e -> e.type().startsWith("SESSION_")).count()));
    }

    private static boolean isRejection(SecurityEvent event) {
        return event.type().contains("REJECT") || event.type().equals("AUTH_FAILED")
                || event.type().equals("LOGIN_THROTTLED");
    }

    private static void styleButton(JButton button) {
        button.setUI(new BasicButtonUI());
        button.setOpaque(true);
        button.setContentAreaFilled(true);
        button.setForeground(Color.WHITE);
        button.setBackground(ACCENT);
        button.setFocusPainted(false);
        button.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0, 108, 91)), new EmptyBorder(10, 14, 10, 14)));
    }

    private static void styleInput(JTextField field) {
        field.setBackground(Color.WHITE);
        field.setForeground(TEXT);
        field.setCaretColor(ACCENT);
        field.setOpaque(true);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER), new EmptyBorder(7, 9, 7, 9)));
    }

    private void styleSeverityFilter() {
        severityFilter.setUI(new BasicComboBoxUI());
        severityFilter.setOpaque(true);
        severityFilter.setBackground(Color.WHITE);
        severityFilter.setForeground(TEXT);
        severityFilter.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        severityFilter.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER), new EmptyBorder(5, 7, 5, 7)));
        severityFilter.setRenderer((list, value, index, selected, focus) -> {
            javax.swing.JLabel item = new javax.swing.JLabel(String.valueOf(value));
            item.setOpaque(true);
            item.setFont(severityFilter.getFont());
            item.setBorder(new EmptyBorder(6, 8, 6, 8));
            item.setForeground(TEXT);
            item.setBackground(selected ? new Color(221, 241, 234) : Color.WHITE);
            return item;
        });
    }

    private static final class EventTableModel extends AbstractTableModel {
        private final String[] columns = {"TIME", "SEVERITY", "EVENT", "ACTOR", "DETAILS"};
        private List<SecurityEvent> events = List.of();

        void setEvents(List<SecurityEvent> events) {
            this.events = events;
            fireTableDataChanged();
        }

        SecurityEvent eventAt(int row) { return events.get(row); }
        @Override public int getRowCount() { return events.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int row, int column) {
            SecurityEvent event = events.get(row);
            return switch (column) {
                case 0 -> TIME_FORMAT.format(event.timestamp());
                case 1 -> event.severity() == Severity.ALERT ? "CRITICAL" : event.severity().name();
                case 2 -> event.type();
                case 3 -> event.actor();
                default -> event.summary();
            };
        }
    }

    private static final class EventCellRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override public Component getTableCellRendererComponent(JTable source, Object value, boolean selected,
                                                                  boolean focused, int row, int column) {
            Component component = super.getTableCellRendererComponent(source, value, selected, focused, row, column);
            if (!selected) {
                component.setBackground(row % 2 == 0 ? PANEL : SOFT_ROW);
                component.setForeground(TEXT);
                if (column == 1) {
                    String severity = String.valueOf(value);
                    component.setForeground("CRITICAL".equals(severity) ? new Color(183, 47, 60)
                            : "WARNING".equals(severity) ? new Color(154, 91, 0) : ACCENT);
                }
            }
            setBorder(new EmptyBorder(0, 10, 0, 10));
            setHorizontalAlignment(column == 1 ? SwingConstants.CENTER : SwingConstants.LEFT);
            return component;
        }
    }

    private final class ActivityChart extends JPanel {
        @Override protected void paintComponent(java.awt.Graphics graphics) {
            super.paintComponent(graphics);
            java.awt.Graphics2D g = (java.awt.Graphics2D) graphics.create();
            try {
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); g.drawString("EVENT ACTIVITY • LOADED TIME RANGE", 6, 12);
                int left = 28, top = 26, bottom = getHeight() - 22, plotWidth = getWidth() - 42;
                int[] buckets = new int[12];
                java.time.Instant min = allEvents.stream().map(SecurityEvent::timestamp).min(java.time.Instant::compareTo).orElse(java.time.Instant.now());
                java.time.Instant maxTime = allEvents.stream().map(SecurityEvent::timestamp).max(java.time.Instant::compareTo).orElse(min.plusSeconds(3600));
                long rangeMillis = Math.max(1, java.time.Duration.between(min, maxTime).toMillis());
                for (SecurityEvent event : allEvents) {
                    long offset = Math.max(0, java.time.Duration.between(min, event.timestamp()).toMillis());
                    int bucket = (int) Math.min(buckets.length - 1, (offset * buckets.length) / rangeMillis);
                    buckets[bucket]++;
                }
                int maximum = Math.max(1, java.util.Arrays.stream(buckets).max().orElse(1));
                g.setColor(BORDER); g.drawLine(left, bottom, left + plotWidth, bottom);
                g.setColor(ACCENT); g.setStroke(new BasicStroke(2f));
                int[] xPoints = new int[buckets.length + 2], yPoints = new int[buckets.length + 2];
                xPoints[0] = left; yPoints[0] = bottom;
                int previousX = -1, previousY = -1;
                for (int i = 0; i < buckets.length; i++) {
                    int x = left + (buckets.length == 1 ? 0 : i * plotWidth / (buckets.length - 1));
                    int y = bottom - (int) ((double) buckets[i] / maximum * Math.max(12, bottom - top));
                    xPoints[i + 1] = x; yPoints[i + 1] = y;
                    if (previousX >= 0) g.drawLine(previousX, previousY, x, y);
                    g.fillOval(x - 3, y - 3, 6, 6); previousX = x; previousY = y;
                }
                xPoints[xPoints.length - 1] = left + plotWidth; yPoints[yPoints.length - 1] = bottom;
                g.setColor(new Color(0, 132, 111, 22)); g.fillPolygon(xPoints, yPoints, xPoints.length);
                g.setColor(MUTED); g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 9));
                DateTimeFormatter axis = DateTimeFormatter.ofPattern("MM-dd HH:mm").withZone(ZoneId.systemDefault());
                String from = axis.format(min), to = axis.format(maxTime);
                g.drawString(from, left, getHeight() - 5);
                g.drawString(to, Math.max(left, left + plotWidth - g.getFontMetrics().stringWidth(to)), getHeight() - 5);
            } finally { g.dispose(); }
        }
    }

    private final class SeverityChart extends JPanel {
        @Override protected void paintComponent(java.awt.Graphics graphics) {
            super.paintComponent(graphics);
            java.awt.Graphics2D g = (java.awt.Graphics2D) graphics.create();
            try {
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); g.drawString("EVENT SEVERITY", 6, 12);
                long critical = allEvents.stream().filter(event -> event.severity() == Severity.ALERT).count();
                long warning = allEvents.stream().filter(event -> event.severity() == Severity.WARNING).count();
                long info = allEvents.stream().filter(event -> event.severity() == Severity.INFO).count();
                long total = critical + warning + info;
                long[] counts = {critical, warning, info};
                String[] labels = {"Critical", "Warning", "Info"};
                Color[] colors = {new Color(194, 55, 67), new Color(220, 145, 37), ACCENT};
                int diameter = Math.max(72, Math.min(104, getHeight() - 38));
                int x = 18, y = 29;
                double start = 90.0;
                for (int i = 0; i < counts.length; i++) {
                    double extent = total == 0 ? -120 : -360.0 * counts[i] / total;
                    g.setColor(total == 0 ? BORDER : colors[i]);
                    g.fill(new java.awt.geom.Arc2D.Double(x, y, diameter, diameter, start, extent, java.awt.geom.Arc2D.PIE));
                    start += extent;
                }
                int hole = diameter / 2;
                g.setColor(PANEL); g.fillOval(x + (diameter - hole) / 2, y + (diameter - hole) / 2, hole, hole);
                g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 15));
                String totalLabel = Long.toString(total);
                g.drawString(totalLabel, x + (diameter - g.getFontMetrics().stringWidth(totalLabel)) / 2, y + diameter / 2 + 5);
                g.setColor(MUTED); g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 8));
                String centerLabel = "EVENTS";
                g.drawString(centerLabel, x + (diameter - g.getFontMetrics().stringWidth(centerLabel)) / 2, y + diameter / 2 + 17);
                int legendX = x + diameter + 24;
                int rowY = 47;
                for (int i = 0; i < counts.length; i++, rowY += 25) {
                    g.setColor(colors[i]); g.fillOval(legendX, rowY - 7, 8, 8);
                    g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10));
                    g.drawString(labels[i], legendX + 14, rowY);
                    String value = Long.toString(counts[i]);
                    g.setColor(MUTED); g.drawString(value, getWidth() - g.getFontMetrics().stringWidth(value) - 10, rowY);
                }
            } finally { g.dispose(); }
        }
    }
}
