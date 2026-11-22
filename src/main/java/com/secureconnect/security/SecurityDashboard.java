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
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
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
    private static final Color BACKGROUND = new Color(13, 19, 32);
    private static final Color PANEL = new Color(22, 31, 49);
    private static final Color ACCENT = new Color(58, 207, 165);
    private static final Color TEXT = new Color(229, 236, 247);
    private static final Color MUTED = new Color(145, 160, 181);
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
            new String[]{"All severities", "INFO", "WARNING", "ALERT"});
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
        frame.setMinimumSize(new Dimension(920, 600));
        frame.setSize(1180, 760);
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

        JButton pauseButton = new JButton("Pause updates");
        styleButton(pauseButton);
        pauseButton.addActionListener(event -> {
            paused = !paused;
            pauseButton.setText(paused ? "Resume updates" : "Pause updates");
            status.setText(paused ? "Updates paused" : "Watching " + SecurityEventLog.logPath());
        });
        titleBlock.add(pauseButton, BorderLayout.EAST);
        header.add(titleBlock, BorderLayout.NORTH);

        JPanel cards = new JPanel(new GridLayout(1, 4, 12, 0));
        cards.setOpaque(false);
        cards.add(metricCard("EVENTS LOADED", totalValue, "Latest 5,000 audit entries"));
        cards.add(metricCard("ATTACK ACTIVITY", attacksValue, "Controlled lab actions"));
        cards.add(metricCard("REJECTIONS", rejectedValue, "Login, replay, and integrity"));
        cards.add(metricCard("SESSION EVENTS", sessionsValue, "Open, close, and expiry"));
        header.add(cards, BorderLayout.SOUTH);
        return header;
    }

    private JPanel metricCard(String label, JLabel value, String caption) {
        JPanel card = new JPanel(new BorderLayout(0, 8));
        card.setBackground(PANEL);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(37, 51, 73)), new EmptyBorder(14, 16, 14, 16)));
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
                BorderFactory.createLineBorder(new Color(37, 51, 73)), new EmptyBorder(16, 16, 16, 16)));

        JPanel tools = new JPanel(new BorderLayout(12, 0));
        tools.setOpaque(false);
        JLabel label = new JLabel("Audit trail");
        label.setForeground(TEXT);
        label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        tools.add(label, BorderLayout.WEST);
        JPanel filters = new JPanel();
        filters.setOpaque(false);
        styleInput(search);
        search.setToolTipText("Search event type, actor, or details");
        severityFilter.setBackground(BACKGROUND);
        severityFilter.setForeground(TEXT);
        filters.add(search);
        filters.add(severityFilter);
        tools.add(filters, BorderLayout.EAST);
        panel.add(tools, BorderLayout.NORTH);

        table.setRowSorter(sorter);
        table.setFillsViewportHeight(true);
        table.setRowHeight(34);
        table.setShowVerticalLines(false);
        table.setGridColor(new Color(37, 51, 73));
        table.setBackground(PANEL);
        table.setForeground(TEXT);
        table.setSelectionBackground(new Color(38, 58, 77));
        table.setSelectionForeground(TEXT);
        table.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        table.getTableHeader().setBackground(new Color(18, 27, 43));
        table.getTableHeader().setForeground(MUTED);
        table.getTableHeader().setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        table.getTableHeader().setPreferredSize(new Dimension(0, 34));
        table.getColumnModel().getColumn(0).setPreferredWidth(150);
        table.getColumnModel().getColumn(1).setPreferredWidth(85);
        table.getColumnModel().getColumn(2).setPreferredWidth(185);
        table.getColumnModel().getColumn(3).setPreferredWidth(120);
        table.getColumnModel().getColumn(4).setPreferredWidth(520);
        table.setDefaultRenderer(Object.class, new EventCellRenderer());
        JScrollPane scroll = new JScrollPane(table);
        scroll.getViewport().setBackground(PANEL);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(37, 51, 73)));
        panel.add(scroll, BorderLayout.CENTER);

        Runnable applyFilters = () -> {
            String needle = search.getText().trim().toLowerCase(Locale.ROOT);
            String severity = (String) severityFilter.getSelectedItem();
            sorter.setRowFilter(new RowFilter<>() {
                @Override public boolean include(Entry<? extends EventTableModel, ? extends Integer> entry) {
                    SecurityEvent event = model.eventAt(entry.getIdentifier());
                    boolean severityMatch = "All severities".equals(severity)
                            || event.severity().name().equals(severity);
                    String searchable = (event.type() + " " + event.actor() + " " + event.summary())
                            .toLowerCase(Locale.ROOT);
                    return severityMatch && (needle.isEmpty() || searchable.contains(needle));
                }
            });
        };
        search.getDocument().addDocumentListener(new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent event) { applyFilters.run(); }
            @Override public void removeUpdate(DocumentEvent event) { applyFilters.run(); }
            @Override public void changedUpdate(DocumentEvent event) { applyFilters.run(); }
        });
        severityFilter.addActionListener(event -> applyFilters.run());
        return panel;
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
                    model.setEvents(events);
                    updateMetrics(events);
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
        button.setForeground(TEXT);
        button.setBackground(new Color(36, 57, 75));
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(54, 83, 101)), new EmptyBorder(8, 12, 8, 12)));
    }

    private static void styleInput(JTextField field) {
        field.setBackground(BACKGROUND);
        field.setForeground(TEXT);
        field.setCaretColor(ACCENT);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(48, 63, 84)), new EmptyBorder(7, 9, 7, 9)));
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
                case 1 -> event.severity().name();
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
                component.setBackground(row % 2 == 0 ? PANEL : new Color(19, 28, 44));
                component.setForeground(TEXT);
                if (column == 1) {
                    String severity = String.valueOf(value);
                    component.setForeground("ALERT".equals(severity) ? new Color(255, 113, 123)
                            : "WARNING".equals(severity) ? new Color(255, 191, 99) : ACCENT);
                }
            }
            setBorder(new EmptyBorder(0, 10, 0, 10));
            setHorizontalAlignment(column == 1 ? SwingConstants.CENTER : SwingConstants.LEFT);
            return component;
        }
    }
}
