package com.secureconnect.client;

import com.secureconnect.keymanagement.IdentityKeys;
import com.secureconnect.security.SecurityDashboard;
import com.secureconnect.security.SecurityEventLog;
import com.secureconnect.security.TlsContexts;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JToggleButton;
import javax.swing.JTabbedPane;
import javax.swing.JFileChooser;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
import java.util.HashMap;
import java.util.Map;
import java.util.Comparator;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/** WhatsApp-style local desktop chat with an inspectable E2EE and security-event view. */
public final class SecureChatDesktop {
    private static final Color APP_BG = new Color(235, 239, 235);
    private static final Color SIDEBAR = new Color(247, 249, 247);
    private static final Color GREEN = new Color(0, 128, 105);
    private static final Color DEEP_GREEN = new Color(0, 104, 86);
    private static final Color CHAT_BG = new Color(232, 223, 211);
    private static final Color TEXT = new Color(31, 45, 48);
    private static final Color MUTED = new Color(105, 121, 123);
    private static final Color LINE = new Color(218, 225, 221);
    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final String initialUsername;
    private final String initialPeer;
    private final String host;
    private final int port;
    private final JFrame frame = new JFrame("SecureConnect | Secure Chat");
    private final JPanel cards = new JPanel(new java.awt.CardLayout());
    private final JTextField usernameField = new JTextField(18);
    private final JTextField peerField = new JTextField(18);
    private final JComboBox<String> actionField = new JComboBox<>(new String[]{"Login", "Register"});
    private final JPasswordField passwordField = new JPasswordField(18);
    private final JPasswordField confirmField = new JPasswordField(18);
    private final JTextField relayPortField = new JTextField(8);
    private final JLabel fingerprintLabel = new JLabel("Peer identity key: load an identity to preview its fingerprint");
    private final JCheckBox fingerprintVerified = new JCheckBox("I verified this fingerprint over a trusted channel");
    private final JLabel loginStatus = new JLabel("Connect to your local SecureConnect relay.");
    private final JLabel connectionLabel = new JLabel("NOT CONNECTED");
    private final JLabel peerHeader = new JLabel("Select a conversation");
    private final JLabel e2eeState = new JLabel("Waiting for authenticated session");
    private final JLabel keyState = new JLabel("Key epoch: —");
    private final JLabel seqState = new JLabel("Next message: —");
    private final JLabel pinState = new JLabel("Peer signature: waiting");
    private final JLabel relayState = new JLabel("Relay visibility: encrypted envelope only");
    private final JPanel messageList = new JPanel();
    private final JTextArea composer = new JTextArea(3, 40);
    private final JButton sendButton = new JButton("Send");
    private final JButton connectButton = new JButton("Connect securely");
    private final JTextArea activityList = new JTextArea();
    private final JTextArea cryptoTrace = readOnlyArea();
    private final JTextArea packetMonitor = readOnlyArea();
    private final JTextArea attackOutput = readOnlyArea();
    private final JTextArea evaluationSummary = readOnlyArea();
    private final JComboBox<String> attackMode = new JComboBox<>(new String[]{"eavesdrop", "tamper", "replay", "key-substitution", "masquerade", "dos"});
    private final JComboBox<String> artifactSelect = new JComboBox<>();
    private final Map<String, Path> exportArtifacts = new java.util.LinkedHashMap<>();
    private final JLabel keysOverview = new JLabel();
    private final JPanel latencyChart = new JPanel() {
        @Override protected void paintComponent(java.awt.Graphics graphics) {
            super.paintComponent(graphics);
            paintLatencyChart((java.awt.Graphics2D) graphics, getWidth(), getHeight());
        }
    };
    private final List<PerformancePoint> performancePoints = new ArrayList<>();
    private volatile Process attackProcess;
    private final ArrayDeque<String> activityLines = new ArrayDeque<>();
    private final Set<String> seenAuditEvents = new HashSet<>();
    private final Map<Long, JLabel> pendingMessageTitles = new HashMap<>();
    private final Set<Long> earlyRelayAcks = new HashSet<>();
    private final BlockingQueue<String> inputQueue = new LinkedBlockingQueue<>();
    private volatile ChatClient client;
    private volatile boolean authenticated;
    private volatile boolean identityVerified;
    private volatile boolean e2eeActive;
    private volatile String currentUsername;
    private volatile String currentPeer;
    private volatile String currentLocalSessionId;
    private volatile String currentPeerSessionId;
    private volatile long currentKeyVersion = -1;
    private final Timer eventTimer = new Timer(2000, event -> refreshSecurityActivity());

    private SecureChatDesktop(String username, String peer, String host, int port) {
        this.initialUsername = username == null ? "Alice" : username;
        this.initialPeer = peer == null ? "Bob" : peer;
        this.host = host;
        this.port = port;
        configureLookAndFeel();
    }

    public static void launch(String[] args) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            System.err.println("SecureConnect desktop chat requires a Windows desktop session.");
            return;
        }
        if (args.length > 5) throw new IllegalArgumentException("desktop syntax: desktop [username] [peer] [host] [port]");
        String username = args.length >= 2 ? args[1] : "Alice";
        String peer = args.length >= 3 ? args[2] : "Bob";
        String host = args.length >= 4 ? args[3] : "127.0.0.1";
        int port = args.length >= 5 ? parsePort(args[4]) : 5050;
        SwingUtilities.invokeLater(() -> new SecureChatDesktop(username, peer, host, port).show());
    }

    private static void configureLookAndFeel() {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); }
        catch (Exception ignored) { }
    }

    private void show() {
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setMinimumSize(new Dimension(1180, 720));
        frame.setSize(1420, 860);
        frame.setLocationByPlatform(true);
        frame.getContentPane().setBackground(APP_BG);
        cards.add(buildLoginPage(), "login");
        cards.add(buildChatPage(), "chat");
        frame.setContentPane(cards);
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosing(WindowEvent event) {
                eventTimer.stop();
                if (authenticated) inputQueue.offer("/logout");
                Process lab = attackProcess;
                if (lab != null && lab.isAlive()) lab.destroy();
            }
            @Override public void windowClosed(WindowEvent event) { eventTimer.stop(); }
        });
        ((java.awt.CardLayout) cards.getLayout()).show(cards, "login");
        frame.setVisible(true);
        usernameField.setText(initialUsername);
        peerField.setText(initialPeer);
        relayPortField.setText(Integer.toString(port));
        updateFingerprintPreview();
        peerField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            private void changed() { fingerprintVerified.setSelected(false); updateFingerprintPreview(); }
            @Override public void insertUpdate(javax.swing.event.DocumentEvent event) { changed(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent event) { changed(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent event) { changed(); }
        });
    }

    private JPanel buildLoginPage() {
        JPanel outer = new JPanel(new GridBagLayoutCompat());
        outer.setBackground(new Color(237, 242, 239));
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE),
                new EmptyBorder(34, 42, 34, 42)));
        card.setPreferredSize(new Dimension(500, 700));
        JLabel logo = new JLabel("SC"); logo.setOpaque(true); logo.setBackground(GREEN); logo.setForeground(Color.WHITE);
        logo.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 21)); logo.setHorizontalAlignment(JLabel.CENTER);
        logo.setPreferredSize(new Dimension(54, 54)); logo.setMaximumSize(new Dimension(54, 54));
        JLabel title = heading("SecureConnect");
        JLabel subtitle = body("A private chat demo with visible end-to-end security.");
        addGap(card, 4); card.add(logo); addGap(card, 18); card.add(title); addGap(card, 5); card.add(subtitle); addGap(card, 28);
        card.add(formLabel("YOUR ACCOUNT")); addGap(card, 7); styleField(usernameField); card.add(usernameField); addGap(card, 14);
        card.add(formLabel("CHAT WITH")); addGap(card, 7); styleField(peerField); card.add(peerField); addGap(card, 14);
        card.add(formLabel("RELAY PORT (5050 DIRECT • 5051 ATTACK PROXY)")); addGap(card, 7); styleField(relayPortField); card.add(relayPortField); addGap(card, 14);
        card.add(formLabel("ACCOUNT ACTION")); addGap(card, 7); actionField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        actionField.setBackground(Color.WHITE); card.add(actionField); addGap(card, 14);
        card.add(formLabel("PASSWORD")); addGap(card, 7); styleField(passwordField); card.add(passwordField); addGap(card, 10);
        card.add(formLabel("CONFIRM PASSWORD (REGISTER ONLY)")); addGap(card, 7); styleField(confirmField); card.add(confirmField); addGap(card, 14);
        fingerprintLabel.setForeground(MUTED); fingerprintLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11)); fingerprintLabel.setAlignmentX(0f);
        fingerprintLabel.setMaximumSize(new Dimension(410, 52));
        card.add(fingerprintLabel); addGap(card, 12);
        fingerprintVerified.setOpaque(false); fingerprintVerified.setForeground(TEXT); fingerprintVerified.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11)); fingerprintVerified.setAlignmentX(0f);
        card.add(fingerprintVerified); addGap(card, 12);
        connectButton.setForeground(Color.WHITE); connectButton.setBackground(GREEN); connectButton.setFocusPainted(false);
        connectButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14)); connectButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        connectButton.addActionListener(event -> connect()); card.add(connectButton); addGap(card, 10);
        loginStatus.setForeground(MUTED); loginStatus.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); loginStatus.setAlignmentX(0f); card.add(loginStatus); addGap(card, 20);
        JLabel note = body("Local demo • TLS to relay • Ed25519-pinned X25519 session • AES-256-GCM messages");
        note.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10)); card.add(note);
        outer.add(card);
        return outer;
    }

    private JPanel buildChatPage() {
        JPanel root = new JPanel(new BorderLayout()); root.setBackground(APP_BG);
        JPanel left = new JPanel(new BorderLayout()); left.setBackground(SIDEBAR); left.setPreferredSize(new Dimension(285, 0));
        JLabel brand = new JLabel("  SecureConnect"); brand.setForeground(GREEN); brand.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 20));
        brand.setBorder(new EmptyBorder(18, 12, 18, 12)); left.add(brand, BorderLayout.NORTH);
        JPanel conversation = new JPanel(new BorderLayout(0, 8)); conversation.setBackground(new Color(232, 241, 236));
        conversation.setBorder(new EmptyBorder(16, 16, 16, 12));
        JLabel avatar = new JLabel("SC"); avatar.setOpaque(true); avatar.setBackground(new Color(183, 218, 205)); avatar.setForeground(DEEP_GREEN);
        avatar.setHorizontalAlignment(JLabel.CENTER); avatar.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16)); avatar.setPreferredSize(new Dimension(44,44));
        JPanel contact = new JPanel(new BorderLayout(10, 0)); contact.setOpaque(false); contact.add(avatar, BorderLayout.WEST);
        JPanel contactInfo = new JPanel(new GridLayout(2, 1)); contactInfo.setOpaque(false); peerHeader.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        connectionLabel.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 10)); connectionLabel.setForeground(MUTED); contactInfo.add(peerHeader); contactInfo.add(connectionLabel);
        contact.add(contactInfo, BorderLayout.CENTER); conversation.add(contact, BorderLayout.NORTH);
        JLabel safety = new JLabel("  🔒  Messages are encrypted end to end"); safety.setForeground(DEEP_GREEN); safety.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        safety.setBorder(new EmptyBorder(10, 0, 8, 0)); conversation.add(safety, BorderLayout.SOUTH); left.add(conversation, BorderLayout.CENTER);
        JButton monitor = new JButton("Open security monitor"); monitor.addActionListener(event -> SecurityDashboard.launch());
        monitor.setFocusPainted(false); monitor.setBackground(Color.WHITE); monitor.setForeground(GREEN); monitor.setBorder(new EmptyBorder(12, 12, 12, 12));
        left.add(monitor, BorderLayout.SOUTH);

        JPanel center = new JPanel(new BorderLayout(0, 0)); center.setBackground(CHAT_BG);
        JPanel chatHeader = new JPanel(new BorderLayout(8, 0)); chatHeader.setBackground(SIDEBAR); chatHeader.setBorder(new EmptyBorder(14, 18, 14, 18));
        JLabel chatTitle = new JLabel("Conversation"); chatTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16)); chatTitle.setForeground(TEXT);
        JLabel tlsBadge = new JLabel("TLS 1.3/1.2  •  LOCAL RELAY"); tlsBadge.setForeground(GREEN); tlsBadge.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        chatHeader.add(chatTitle, BorderLayout.WEST); chatHeader.add(tlsBadge, BorderLayout.EAST); center.add(chatHeader, BorderLayout.NORTH);
        messageList.setLayout(new BoxLayout(messageList, BoxLayout.Y_AXIS)); messageList.setBackground(CHAT_BG); messageList.setBorder(new EmptyBorder(16, 22, 16, 22));
        JScrollPane conversationScroll = new JScrollPane(messageList); conversationScroll.setBorder(null); conversationScroll.getViewport().setBackground(CHAT_BG);
        JPanel inputArea = new JPanel(new BorderLayout(10, 0)); inputArea.setBackground(new Color(242, 245, 242)); inputArea.setBorder(new EmptyBorder(12, 16, 12, 16));
        composer.setLineWrap(true); composer.setWrapStyleWord(true); composer.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14)); composer.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(9, 12, 9, 12)));
        JScrollPane composerScroll = new JScrollPane(composer); composerScroll.setBorder(null); inputArea.add(composerScroll, BorderLayout.CENTER);
        sendButton.setForeground(Color.WHITE); sendButton.setBackground(GREEN); sendButton.setFocusPainted(false); sendButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        sendButton.addActionListener(event -> send()); inputArea.add(sendButton, BorderLayout.EAST);
        JPanel conversationView = new JPanel(new BorderLayout()); conversationView.add(conversationScroll, BorderLayout.CENTER); conversationView.add(inputArea, BorderLayout.SOUTH);
        JTabbedPane views = new JTabbedPane();
        views.addTab("Chat", conversationView);
        views.addTab("Crypto trace", buildCryptoView());
        views.addTab("Network", buildNetworkView());
        views.addTab("Keys & session", buildKeysView());
        views.addTab("Attack lab", buildAttackView());
        views.addTab("Evaluation", buildEvaluationView());
        center.add(views, BorderLayout.CENTER);

        JPanel right = new JPanel(new BorderLayout(0, 12)); right.setBackground(SIDEBAR); right.setPreferredSize(new Dimension(340, 0));
        right.setBorder(new EmptyBorder(18, 16, 16, 16));
        JLabel securityTitle = new JLabel("SECURITY DETAILS"); securityTitle.setForeground(GREEN); securityTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11)); right.add(securityTitle, BorderLayout.NORTH);
        JPanel security = new JPanel(); security.setLayout(new BoxLayout(security, BoxLayout.Y_AXIS)); security.setBackground(SIDEBAR);
        addSecurityRow(security, "TRANSPORT", "TLS protects client ↔ relay", new Color(0, 128, 105));
        addSecurityRow(security, "ACCOUNT AUTH", "Argon2id password verifier • TLS-bound session", new Color(0, 128, 105));
        addSecurityRow(security, "IDENTITY", pinState, new Color(0, 128, 105));
        addSecurityRow(security, "SESSION", e2eeState, new Color(0, 128, 105));
        addSecurityRow(security, "MESSAGE KEY", keyState, new Color(0, 128, 105));
        addSecurityRow(security, "REPLAY CHECK", seqState, new Color(0, 128, 105));
        addSecurityRow(security, "RELAY VIEW", relayState, new Color(0, 128, 105));
        JLabel flowTitle = new JLabel("MESSAGE JOURNEY"); flowTitle.setForeground(GREEN); flowTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        flowTitle.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT); flowTitle.setBorder(new EmptyBorder(18, 0, 8, 0)); security.add(flowTitle);
        security.add(body("1  Compose plaintext on sender device")); addGap(security, 6);
        security.add(body("2  AES-256-GCM seals it with a fresh nonce")); addGap(security, 6);
        security.add(body("3  Relay routes opaque encrypted envelope")); addGap(security, 6);
        security.add(body("4  Receiver checks sequence + GCM tag")); addGap(security, 6);
        security.add(body("5  Plaintext appears only after verification")); addGap(security, 6);
        security.add(body("Key epochs derive from the session root every 10 messages; this demo does not implement a forward-secure ratchet."));
        JLabel activityTitle = new JLabel("LIVE SECURITY ACTIVITY"); activityTitle.setForeground(GREEN); activityTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        activityTitle.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT); activityTitle.setBorder(new EmptyBorder(18, 0, 6, 0)); security.add(activityTitle);
        activityList.setEditable(false); activityList.setLineWrap(true); activityList.setWrapStyleWord(true); activityList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        activityList.setBackground(new Color(241, 246, 243)); activityList.setForeground(TEXT); activityList.setBorder(new EmptyBorder(8, 8, 8, 8));
        activityList.setColumns(24); activityList.setRows(8);
        JScrollPane eventScroll = new JScrollPane(activityList); eventScroll.setPreferredSize(new Dimension(250, 150)); eventScroll.setBorder(BorderFactory.createLineBorder(LINE));
        eventScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER); security.add(eventScroll);
        JScrollPane rightScroll = new JScrollPane(security); rightScroll.setBorder(null); rightScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER); rightScroll.getViewport().setBackground(SIDEBAR); right.add(rightScroll, BorderLayout.CENTER);
        root.add(left, BorderLayout.WEST); root.add(center, BorderLayout.CENTER); root.add(right, BorderLayout.EAST);
        sendButton.setEnabled(false); composer.setEnabled(false);
        return root;
    }

    private JPanel buildCryptoView() {
        JPanel panel = tabPanel("LIVE MESSAGE CRYPTOGRAPHY", "This trace is populated from the sender and receiver callbacks after the real AES-GCM operations.");
        cryptoTrace.setText("Waiting for a real message. No sample ciphertext is generated by the UI.\n\n"
                + "AES-256-GCM • 256-bit key • fresh 96-bit nonce • 128-bit tag\n"
                + "Secret keys and private keys are never displayed.");
        panel.add(wrapArea(cryptoTrace), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildNetworkView() {
        JPanel panel = tabPanel("LIVE NETWORK COMMUNICATION", "Client → TLS relay → recipient client. The relay receives routing metadata and the opaque SC1 envelope.");
        JLabel route = heading("SENDER DEVICE   →   LOCAL RELAY   →   RECIPIENT DEVICE");
        route.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        panel.add(route, BorderLayout.NORTH);
        packetMonitor.setText("Waiting for packet events from the connected ChatClient.\n"
                + "The handshake provides authenticated client session IDs. Packet identity is sender session ID + sequence; there is no separate message UUID.\n\n");
        panel.add(wrapArea(packetMonitor), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildKeysView() {
        JPanel panel = tabPanel("KEY MANAGEMENT & SESSION LIFECYCLE", "Safe metadata only. Secret AES keys, X25519 private keys, and session roots are never rendered.");
        keysOverview.setForeground(TEXT); keysOverview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        keysOverview.setBorder(new EmptyBorder(18, 18, 18, 18));
        keysOverview.setVerticalAlignment(JLabel.TOP);
        JButton newSession = new JButton("End session and establish a fresh one");
        newSession.addActionListener(event -> {
            if (authenticated) {
                inputQueue.offer("/logout");
                addActivity("SESSION", "User requested a fresh connection; current session keys will be cleared on logout.");
                loginStatus.setText("Session ended. Log in again to create a fresh authenticated X25519 session.");
            } else {
                ((java.awt.CardLayout) cards.getLayout()).show(cards, "login");
            }
        });
        JPanel content = new JPanel(new BorderLayout(0, 16)); content.setOpaque(false);
        content.add(keysOverview, BorderLayout.CENTER); content.add(newSession, BorderLayout.SOUTH);
        panel.add(content, BorderLayout.CENTER);
        updateKeysOverview();
        return panel;
    }

    private JPanel buildAttackView() {
        JPanel panel = tabPanel("CONTROLLED LOCAL ATTACK LAB", "Runs the existing attack proxy against a loopback relay. For proxy modes, reconnect this UI through port 5051 after starting the proxy.");
        JPanel controls = new JPanel(new BorderLayout(8, 0)); controls.setOpaque(false);
        controls.add(attackMode, BorderLayout.CENTER);
        JButton start = new JButton("Run / start selected simulation"); start.addActionListener(event -> startAttackSimulation());
        JButton stop = new JButton("Stop proxy"); stop.addActionListener(event -> stopAttackProxy());
        JPanel actions = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 8, 0)); actions.setOpaque(false); actions.add(start); actions.add(stop);
        JPanel north = new JPanel(new BorderLayout(0, 10)); north.setOpaque(false); north.add(body("Eavesdrop, tamper, replay, key substitution and masquerade run as a real local TLS proxy. DoS runs the bounded 20-connection baseline. Do not point this lab at a non-local server."), BorderLayout.NORTH); north.add(controls, BorderLayout.CENTER); north.add(actions, BorderLayout.SOUTH);
        panel.add(north, BorderLayout.NORTH);
        attackOutput.setText("No attack simulation started from this window yet.\n"
                + "Proxy modes require SECURECONNECT_TLS_KEYSTORE / trust settings used by the relay. The child process inherits this app's environment.");
        panel.add(wrapArea(attackOutput), BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildEvaluationView() {
        JPanel panel = tabPanel("TESTING & PERFORMANCE", "Charts and rates are loaded from existing CSV artifacts. The UI does not invent test outcomes or timings.");
        JButton refresh = new JButton("Refresh results"); refresh.addActionListener(event -> refreshEvaluation());
        JButton runCrypto = new JButton("Run crypto benchmark"); runCrypto.addActionListener(event -> runCryptoBenchmark());
        JButton runSecurity = new JButton("Run 500 security-control trials"); runSecurity.addActionListener(event -> runSecurityEvaluation());
        JButton export = new JButton("Export latest CSV…"); export.addActionListener(event -> exportLatestCsv());
        JPanel buttons = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT)); buttons.setOpaque(false); buttons.add(refresh); buttons.add(runCrypto); buttons.add(runSecurity); buttons.add(artifactSelect); buttons.add(export);
        evaluationSummary.setText("Select Refresh results to load the latest saved benchmark and security evaluation CSV files.\n"
                + "JUnit status is read from Maven Surefire reports, when available.");
        latencyChart.setBackground(Color.WHITE); latencyChart.setPreferredSize(new Dimension(700, 260));
        JScrollPane summaryScroll = wrapArea(evaluationSummary);
        summaryScroll.setPreferredSize(new Dimension(760, 320));
        JSplitPane resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, latencyChart, summaryScroll);
        resultsSplit.setResizeWeight(0.42); resultsSplit.setContinuousLayout(true); resultsSplit.setBorder(null);
        panel.add(buttons, BorderLayout.NORTH); panel.add(resultsSplit, BorderLayout.CENTER);
        refreshEvaluation();
        return panel;
    }

    private static JPanel tabPanel(String title, String description) {
        JPanel panel = new JPanel(new BorderLayout(0, 14)); panel.setBackground(new Color(247, 249, 247)); panel.setBorder(new EmptyBorder(22, 24, 22, 24));
        JPanel heading = new JPanel(); heading.setOpaque(false); heading.setLayout(new BoxLayout(heading, BoxLayout.Y_AXIS));
        JLabel titleLabel = heading(title); titleLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18)); heading.add(titleLabel); addGap(heading, 5); heading.add(body(description));
        panel.add(heading, BorderLayout.NORTH); return panel;
    }

    private static JScrollPane wrapArea(JTextArea area) {
        area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setBackground(Color.WHITE); area.setForeground(TEXT); area.setBorder(new EmptyBorder(12, 12, 12, 12));
        JScrollPane scroll = new JScrollPane(area); scroll.setBorder(BorderFactory.createLineBorder(LINE)); return scroll;
    }

    private static JTextArea readOnlyArea() { JTextArea area = new JTextArea(); area.setEditable(false); return area; }

    private void startAttackSimulation() {
        String mode = ((String) attackMode.getSelectedItem());
        if (attackProcess != null && attackProcess.isAlive()) { addAttackOutput("An attack proxy is already running."); return; }
        if (!"127.0.0.1".equalsIgnoreCase(host) && !"localhost".equalsIgnoreCase(host)) {
            addAttackOutput("Blocked: the attack lab only supports localhost relay targets."); return;
        }
        try {
            String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
            if (!Files.exists(Path.of(java))) java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            List<String> command = new ArrayList<>(List.of(java, "-cp", System.getProperty("java.class.path"),
                    "com.secureconnect.Main", "attack-proxy", mode));
            ProcessBuilder builder;
            if ("dos".equals(mode)) {
                builder = new ProcessBuilder(command);
                addAttackOutput("Starting the bounded DoS baseline against " + host + ":" + port + ".");
            } else {
                command.addAll(List.of("5051", host, Integer.toString(port)));
                builder = new ProcessBuilder(command);
                addAttackOutput("Starting " + mode + " proxy on localhost:5051 → " + host + ":" + port + ". Your current session stays connected until the proxy confirms it is listening.");
            }
            builder.redirectErrorStream(true);
            attackProcess = builder.start();
            Process launched = attackProcess;
            Thread reader = new Thread(() -> readProcessOutput(launched, attackOutput, "[ATTACK LAB] "), "secureconnect-attack-ui-output");
            reader.setDaemon(true); reader.start();
            if ("dos".equals(mode)) addActivity("ATTACK", "Started bounded localhost DoS baseline.");
            else addActivity("ATTACK", "Started local " + mode + " proxy on port 5051.");
        } catch (IOException exception) { addAttackOutput("Could not start the simulation: " + safeMessage(exception)); }
    }

    private void stopAttackProxy() {
        Process process = attackProcess;
        if (process == null || !process.isAlive()) { addAttackOutput("No active proxy process."); return; }
        process.destroy();
        addAttackOutput("Stopping the local proxy. Connections using port 5051 will close.");
        relayPortField.setText(Integer.toString(port));
        if (authenticated) inputQueue.offer("/logout");
    }

    private void runSecurityEvaluation() {
        try {
            String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
            if (!Files.exists(Path.of(java))) java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            ProcessBuilder builder = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "com.secureconnect.Main", "security-evaluation", "500").redirectErrorStream(true);
            Process process = builder.start();
            addEvalLine("Starting real message-layer security evaluation in background…");
            Thread reader = new Thread(() -> readProcessOutput(process, evaluationSummary, ""), "secureconnect-evaluation-output");
            reader.setDaemon(true); reader.start();
            addActivity("EVALUATION", "Started 500-trial-per-control security evaluation.");
        } catch (IOException exception) { addEvalLine("Could not start evaluation: " + safeMessage(exception)); }
    }

    private void runCryptoBenchmark() {
        try {
            String java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString();
            if (!Files.exists(Path.of(java))) java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            ProcessBuilder builder = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "com.secureconnect.Main", "benchmark", "200", "100").redirectErrorStream(true);
            Process process = builder.start();
            addEvalLine("Starting real AES-GCM crypto benchmark (200 measured operations, 100 warm-ups per metric/payload)…");
            Thread reader = new Thread(() -> readProcessOutput(process, evaluationSummary, ""), "secureconnect-crypto-benchmark-ui-output");
            reader.setDaemon(true); reader.start();
            addActivity("EVALUATION", "Started 200-sample crypto benchmark in background.");
        } catch (IOException exception) { addEvalLine("Could not start crypto benchmark: " + safeMessage(exception)); }
    }

    private void readProcessOutput(Process process, JTextArea target, String prefix) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
            String line; while ((line = reader.readLine()) != null) {
                String output = prefix + line;
                if (target == attackOutput && line.startsWith("[PROXY_READY]")) {
                    runOnUi(() -> {
                        appendArea(target, output);
                        relayPortField.setText("5051");
                        addAttackOutput("Proxy is listening. The current direct session will now close; reconnect both users through port 5051.");
                        if (authenticated) inputQueue.offer("/logout");
                    });
                } else runOnUi(() -> appendArea(target, output));
            }
            int exit = process.waitFor(); runOnUi(() -> { appendArea(target, "Process exited with code " + exit + "."); if (target == evaluationSummary) refreshEvaluation(); });
        } catch (IOException exception) { runOnUi(() -> appendArea(target, "Output stream ended: " + safeMessage(exception))); }
        catch (InterruptedException exception) { Thread.currentThread().interrupt(); }
    }

    private void addAttackOutput(String line) { appendArea(attackOutput, line); }
    private void addEvalLine(String line) { appendArea(evaluationSummary, line); }
    private static void appendArea(JTextArea area, String line) { area.append(line + "\n"); area.setCaretPosition(area.getDocument().getLength()); }

    private void exportLatestCsv() {
        Path selected = exportArtifacts.get((String) artifactSelect.getSelectedItem());
        if (selected == null || !Files.isRegularFile(selected)) { addEvalLine("No CSV artifact is available yet."); return; }
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(selected.getFileName().toFile());
        if (chooser.showSaveDialog(frame) != JFileChooser.APPROVE_OPTION) return;
        try { Files.copy(selected, chooser.getSelectedFile().toPath(), StandardCopyOption.REPLACE_EXISTING); addEvalLine("Exported " + selected.getFileName() + " to " + chooser.getSelectedFile()); }
        catch (IOException exception) { addEvalLine("Export failed: " + safeMessage(exception)); }
    }

    private void refreshEvaluation() {
        Path results = Path.of("experiments", "results");
        performancePoints.clear();
        exportArtifacts.clear(); artifactSelect.removeAllItems();
        StringBuilder text = new StringBuilder("Evaluation artifacts (actual saved data)\n\n");
        try {
            if (Files.isDirectory(results)) {
                Path network = latestFile(results, "secureconnect-network-", "-summary.csv");
                Path crypto = latestCryptoSummary(results);
                Path security = latestFile(results, "secureconnect-security-", ".csv");
                if (network != null) {
                    text.append("Latest TLS relay benchmark: ").append(network.getFileName()).append('\n');
                    addExportArtifact(network);
                    List<String> rows = Files.readAllLines(network, java.nio.charset.StandardCharsets.UTF_8);
                    text.append("Payload     mean latency     median       p95       throughput\n");
                    for (int i = 1; i < rows.size(); i++) { String[] f = rows.get(i).split(",", -1); if (f.length < 9) continue;
                        int bytes = Integer.parseInt(f[1]); double meanMs = Double.parseDouble(f[4]) / 1_000_000.0;
                        text.append(String.format(Locale.ROOT, "%-10s %8.3f ms %8.3f ms %8.3f ms %8.2f MiB/s%n", formatBytes(bytes), meanMs, Double.parseDouble(f[5]) / 1_000_000.0, Double.parseDouble(f[6]) / 1_000_000.0, Double.parseDouble(f[8])));
                        performancePoints.add(new PerformancePoint(formatBytes(bytes), meanMs));
                    }
                    text.append("\n");
                } else text.append("No TLS relay benchmark summary CSV found.\n\n");
                if (crypto != null) {
                    addExportArtifact(crypto); text.append("Latest cryptography microbenchmark: ").append(crypto.getFileName()).append('\n');
                    text.append("Payload     operation       mean       median       p95       throughput\n");
                    List<String> cryptoRows = Files.readAllLines(crypto, java.nio.charset.StandardCharsets.UTF_8);
                    for (int i=1;i<cryptoRows.size();i++) { String[] f=cryptoRows.get(i).split(",",-1); if (f.length<10) continue;
                        int bytes=Integer.parseInt(f[1]); String metric=f[2]; double mean=Double.parseDouble(f[5])/1000.0;
                        text.append(String.format(Locale.ROOT,"%-10s %-14s %8.2f µs %8.2f µs %8.2f µs %8.2f MiB/s%n",formatBytes(bytes),metric,mean,Double.parseDouble(f[6])/1000.0,Double.parseDouble(f[7])/1000.0,Double.parseDouble(f[9])));
                    }
                    text.append('\n');
                }
                if (security != null) {
                    text.append("Latest security evaluation: ").append(security.getFileName()).append('\n');
                    addExportArtifact(security);
                    for (String row : Files.readAllLines(security, java.nio.charset.StandardCharsets.UTF_8).stream().skip(1).toList()) text.append("  ").append(row.replace(',', ' ')).append('\n');
                    text.append("These are local message-layer control trials, not network attack rates.\n\n");
                } else text.append("No security-evaluation CSV found yet.\n\n");
            } else text.append("No experiments/results folder found. Run an evaluation or benchmark first.\n\n");
            Path reports = Path.of("target", "surefire-reports");
            if (Files.isDirectory(reports)) {
                List<Path> xml;
                try (var files = Files.list(reports)) { xml = files.filter(path -> path.getFileName().toString().startsWith("TEST-") && path.toString().endsWith(".xml")).toList(); }
                if (xml.isEmpty()) text.append("JUnit: no Surefire XML result files found.\n");
                else { int tests=0, failures=0, errors=0, skipped=0; for (Path report : xml) { String xmlText=Files.readString(report); tests+=xmlAttribute(xmlText,"tests"); failures+=xmlAttribute(xmlText,"failures"); errors+=xmlAttribute(xmlText,"errors"); skipped+=xmlAttribute(xmlText,"skipped"); }
                    text.append(String.format(Locale.ROOT, "JUnit Surefire reports: %d tests, %d failures, %d errors, %d skipped (saved report data).%n", tests, failures, errors, skipped)); }
            } else text.append("JUnit: Maven Surefire reports have not been generated in this checkout.\n");
        } catch (Exception exception) { text.append("Could not read evaluation artifacts: ").append(safeMessage(exception)); }
        if (artifactSelect.getItemCount() > 0) artifactSelect.setSelectedIndex(0);
        evaluationSummary.setText(text.toString()); latencyChart.repaint();
    }

    private void addExportArtifact(Path path) {
        String label = path.getFileName().toString();
        exportArtifacts.put(label, path); artifactSelect.addItem(label);
    }

    private static Path latestCryptoSummary(Path directory) throws IOException {
        try (var files = Files.list(directory)) {
            return files.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().startsWith("secureconnect-")
                            && !path.getFileName().toString().startsWith("secureconnect-network-")
                            && !path.getFileName().toString().startsWith("secureconnect-security-")
                            && path.getFileName().toString().endsWith("-summary.csv"))
                    .max(Comparator.comparingLong(path -> path.toFile().lastModified())).orElse(null);
        }
    }

    private static Path latestFile(Path directory, String prefix, String suffix) throws IOException {
        try (var files = Files.list(directory)) { return files.filter(Files::isRegularFile)
                .filter(path -> path.getFileName().toString().startsWith(prefix) && path.getFileName().toString().endsWith(suffix))
                .max(Comparator.comparingLong(path -> path.toFile().lastModified())).orElse(null); }
    }
    private static int xmlAttribute(String xml, String name) { java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("\\b" + name + "=\\\"(\\d+)\\\"").matcher(xml); return matcher.find() ? Integer.parseInt(matcher.group(1)) : 0; }
    private static String formatBytes(int bytes) { return bytes >= 1024 * 1024 ? (bytes / (1024 * 1024)) + " MB" : (bytes / 1024) + " KB"; }

    private void paintLatencyChart(java.awt.Graphics2D g, int width, int height) {
        g.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING, java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(Color.WHITE); g.fillRect(0, 0, width, height); g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14)); g.drawString("Latest recorded TLS relay mean latency", 18, 24);
        if (performancePoints.isEmpty()) { g.setColor(MUTED); g.drawString("No network benchmark CSV loaded", 24, 62); return; }
        int left=60, top=48, bottom=height-38, plotH=bottom-top, group=Math.max(1,(width-left-30)/performancePoints.size());
        double max=performancePoints.stream().mapToDouble(PerformancePoint::meanMs).max().orElse(1); max=Math.max(max,0.1);
        for (int i=0;i<=4;i++) { int y=bottom-i*plotH/4; g.setColor(new Color(229,235,232)); g.drawLine(left,y,width-18,y); g.setColor(MUTED); g.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,10)); g.drawString(String.format(Locale.ROOT,"%.2f ms",max*i/4),4,y+4); }
        for (int i=0;i<performancePoints.size();i++) { PerformancePoint point=performancePoints.get(i); int barH=(int)(point.meanMs()/max*(plotH-8)); int x=left+i*group+group/4; int barW=Math.max(20,group/2); g.setColor(GREEN); g.fillRoundRect(x,bottom-barH,barW,barH,8,8); g.setColor(TEXT); g.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,11)); g.drawString(point.label(),x,bottom+18); g.drawString(String.format(Locale.ROOT,"%.2f",point.meanMs()),x,bottom-barH-5); }
    }

    private void updateKeysOverview() {
        String user = currentUsername == null ? initialUsername : currentUsername;
        String peer = currentPeer == null ? initialPeer : currentPeer;
        String identity = "Pinned fingerprint loaded; signature verification is pending";
        try { if (identityVerified) identity = "Pinned peer Ed25519 SHA-256 fingerprint: " + IdentityKeys.fingerprint(trustedKeyFor(peer)); } catch (Exception ignored) { }
        String session = e2eeActive ? "Authenticated X25519 + HKDF session active" : (authenticated ? "TLS account authenticated; waiting for peer key verification" : "No active account connection");
        String epoch = currentKeyVersion < 0 ? "No message key epoch negotiated" : "Current message key epoch: " + currentKeyVersion + " (derivation refresh each 10-message epoch)";
        keysOverview.setText("<html><b>Participants</b><br>" + htmlEscape(user) + " ↔ " + htmlEscape(peer)
                + "<br><br><b>Transport</b><br>TLS client ↔ relay; relay receives encrypted envelopes only."
                + "<br><br><b>Identity authentication</b><br>Ed25519 signature checked against pinned public identity.<br>"
                + htmlEscape(identity) + "<br><br><b>Session agreement</b><br>X25519 ephemeral agreement → HKDF-SHA-256 session root.<br>"
                + htmlEscape(session) + "<br><br><b>Message protection</b><br>AES-256-GCM; fresh nonce per message; 128-bit authentication tag.<br>"
                + htmlEscape(epoch) + "<br><br><b>Replay protection</b><br>Session-local expected sequence rejects duplicate and out-of-order delivery."
                + "<br><br><b>Session identifiers</b><br>Local: " + htmlEscape(displayId(currentLocalSessionId))
                + "<br>Peer: " + htmlEscape(displayId(currentPeerSessionId))
                + "<br><br><b>Lifecycle note</b><br>Epoch refresh is the implemented key schedule; this is not a forward-secure Double Ratchet.</html>");
    }

    private void updateCryptoTrace(boolean outgoing, String sender, String recipient, String plaintext,
                                   String envelope, long sequence, long version, long elapsedNanos) {
        try {
            byte[] raw = java.util.Base64.getDecoder().decode(envelope.substring("SC1.".length()));
            byte[] nonce = Arrays.copyOfRange(raw, 0, 12);
            byte[] tag = Arrays.copyOfRange(raw, raw.length - 16, raw.length);
            byte[] ciphertext = Arrays.copyOfRange(raw, 12, raw.length - 16);
            byte[] plain = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            StringBuilder trace = new StringBuilder();
            trace.append(outgoing ? "ENCRYPTION • sender endpoint" : "DECRYPTION • receiver endpoint").append('\n')
                    .append("Message route: ").append(sender).append(" → ").append(recipient).append("\nSequence: ").append(sequence).append(" • key epoch: ").append(version).append('\n')
                    .append("Algorithm: AES-256-GCM • key size: 256 bits\nOperation time (measured around actual client operation): ").append(String.format(Locale.ROOT,"%.3f µs",elapsedNanos/1000.0)).append('\n')
                    .append("\nPlaintext (UTF-8):\n").append(plaintext).append("\nPlaintext bytes (hex):\n").append(hex(plain)).append('\n')
                    .append("\nNonce / IV (96-bit, hex):\n").append(hex(nonce)).append('\n')
                    .append("\nCiphertext (hex):\n").append(hex(ciphertext)).append('\n')
                    .append("\nAuthentication tag (128-bit, hex):\n").append(hex(tag)).append('\n')
                    .append("\nEnvelope (Base64, exact protocol value):\n").append(envelope).append('\n')
                    .append(outgoing ? "\nResult: encrypted packet sent to the relay." : "\nResult: GCM authentication passed; plaintext was released locally.");
            cryptoTrace.setText(trace.toString());
            String senderSessionId = sender.equals(currentUsername) ? currentLocalSessionId : currentPeerSessionId;
            appendArea(packetMonitor, (outgoing ? "OUTBOUND" : "INBOUND") + " • " + LocalTime.now().format(CLOCK)
                    + " • msg=" + displayId(senderSessionId) + ":" + sequence + " • epoch=" + version + " • " + envelope.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
                    + " envelope bytes • SC1 ciphertext only at relay • " + sender + " → " + recipient);
            updateKeysOverview();
        } catch (RuntimeException exception) { cryptoTrace.setText("Could not decode the actual message envelope: " + safeMessage(exception)); }
    }

    private static String hex(byte[] bytes) { StringBuilder out=new StringBuilder(bytes.length*2); for(byte value:bytes) out.append(String.format(Locale.ROOT,"%02X",value)); return out.toString(); }
    private static String displayId(String value) { return value == null || value.isBlank() ? "pending" : value; }
    private record PerformancePoint(String label, double meanMs) { }

    private void connect() {
        if (client != null) return;
        String username = usernameField.getText().trim(); String peer = peerField.getText().trim();
        final int selectedPort;
        try { selectedPort = parsePort(relayPortField.getText().trim()); }
        catch (IllegalArgumentException exception) { loginStatus.setText("Relay port must be between 1 and 65535."); return; }
        String action = ((String) actionField.getSelectedItem()).toLowerCase(java.util.Locale.ROOT);
        char[] password = passwordField.getPassword(); char[] confirmation = confirmField.getPassword();
        passwordField.setText(""); confirmField.setText("");
        if (!username.matches("[A-Za-z0-9_-]{1,32}") || !peer.matches("[A-Za-z0-9_-]{1,32}") || username.equalsIgnoreCase(peer)) {
            Arrays.fill(password, '\0'); Arrays.fill(confirmation, '\0');
            loginStatus.setText("Enter two different valid account names."); return;
        }
        if (password.length == 0 || ("register".equals(action) && !Arrays.equals(password, confirmation))) {
            Arrays.fill(password, '\0'); Arrays.fill(confirmation, '\0');
            loginStatus.setText("Password is required; registration passwords must match."); return;
        }
        if (!fingerprintVerified.isSelected()) {
            Arrays.fill(password, '\0'); Arrays.fill(confirmation, '\0');
            loginStatus.setText("Compare the peer fingerprint out of band, then confirm it here."); return;
        }
        String pinnedKey;
        try {
            pinnedKey = trustedKeyFor(peer);
            PublicKey key = IdentityKeys.decodePinnedPublicKey(pinnedKey);
            fingerprintLabel.setText("Pinned peer SHA-256: " + IdentityKeys.fingerprint(pinnedKey));
            if (key == null) throw new IllegalArgumentException("Peer key could not be loaded.");
        } catch (Exception exception) {
            Arrays.fill(password, '\0'); Arrays.fill(confirmation, '\0');
            loginStatus.setText("Could not load pinned peer key: " + exception.getMessage()); return;
        }
        connectButton.setEnabled(false); loginStatus.setText("Opening TLS connection and authenticating…");
        Bridge bridge = new Bridge(action, password, confirmation);
        ChatClient.Listener listener = new ChatClient.Listener() {
            @Override public void onAuthenticated(String name) { runOnUi(() -> authenticated(name, peer)); }
            @Override public void onStatus(String message) { runOnUi(() -> setStatus(message)); }
            @Override public void onSessionReady(String name, String localSessionId, String peerSessionId) { runOnUi(() -> sessionReady(name, localSessionId, peerSessionId)); }
            @Override public void onKeyVersion(long version) { runOnUi(() -> keyVersion(version)); }
            @Override public void onOutgoingMeasured(String text, String envelope, long sequence, long version, long nanos) {
                runOnUi(() -> { addMessage(true, text, envelope, sequence, version); updateCryptoTrace(true, currentUsername, currentPeer, text, envelope, sequence, version, nanos); });
            }
            @Override public void onDelivered(String name, long sequence) { runOnUi(() -> markDelivered(sequence)); }
            @Override public void onIncomingMeasured(String sender, String text, String envelope, long sequence, long version, long nanos) {
                runOnUi(() -> { addMessage(false, text, envelope, sequence, version); updateCryptoTrace(false, sender, currentUsername, text, envelope, sequence, version, nanos); });
            }
            @Override public void onSecurity(String message) { runOnUi(() -> addActivity("SECURITY", message)); }
            @Override public void onDisconnected() { runOnUi(() -> disconnected()); }
        };
        Thread thread = new Thread(() -> {
            try {
                ChatClient chatClient = new ChatClient(host, selectedPort, username, peer,
                        IdentityKeys.loadPrivate(username), IdentityKeys.decodePinnedPublicKey(pinnedKey),
                        TlsContexts.clientContextFromEnvironment(), new ClientConsole(bridge), listener);
                client = chatClient;
                chatClient.run();
            } catch (Exception exception) {
                Arrays.fill(password, '\0'); Arrays.fill(confirmation, '\0');
                runOnUi(() -> { loginStatus.setText("Connection failed: " + safeMessage(exception)); connectButton.setEnabled(true); });
            }
        }, "secureconnect-desktop-client");
        thread.setDaemon(true); thread.start();
    }

    private String trustedKeyFor(String peer) throws IOException {
        String env = System.getenv("SECURECONNECT_TRUSTED_PEER_KEY");
        if (env != null && !env.isBlank()) return env.trim();
        return Files.readString(IdentityKeys.publicPath(peer), java.nio.charset.StandardCharsets.UTF_8).trim();
    }

    private void updateFingerprintPreview() {
        String peer = peerField.getText().trim();
        try {
            String key = trustedKeyFor(peer);
            fingerprintLabel.setText("<html>Verify out of band<br>SHA-256: " + IdentityKeys.fingerprint(key) + "</html>");
        } catch (Exception exception) {
            fingerprintLabel.setText("Peer key unavailable. Generate its identity or set SECURECONNECT_TRUSTED_PEER_KEY.");
        }
    }

    private void authenticated(String username, String peer) {
        this.currentUsername = username; this.currentPeer = peer; this.authenticated = true;
        this.identityVerified = false; this.e2eeActive = false; this.currentKeyVersion = -1;
        this.currentLocalSessionId = null; this.currentPeerSessionId = null;
        setWrappedLabel(pinState, "Peer signature: waiting for signed key exchange");
        setWrappedLabel(e2eeState, "Waiting for authenticated session");
        setWrappedLabel(keyState, "Key epoch: —");
        setWrappedLabel(seqState, "Waiting for first verified message");
        ((java.awt.CardLayout) cards.getLayout()).show(cards, "chat");
        peerHeader.setText(peer); connectionLabel.setText("ONLINE  •  ACCOUNT AUTHENTICATED"); connectionLabel.setForeground(GREEN);
        setStatus("TLS connection authenticated as " + username + ". Waiting for " + peer + " to establish an E2EE session.");
        sendButton.setEnabled(false); composer.setEnabled(false); eventTimer.start(); refreshSecurityActivity();
        addActivity("TLS", "Account authentication succeeded; connection-bound session active.");
        appendArea(packetMonitor, "TLS connection authenticated: " + username + " → relay " + host + ":" + relayPortField.getText().trim() + " • " + LocalTime.now().format(CLOCK));
        updateKeysOverview();
    }

    private void sessionReady(String peer, String localSessionId, String peerSessionId) {
        currentLocalSessionId = localSessionId; currentPeerSessionId = peerSessionId;
        identityVerified = true; e2eeActive = true;
        pendingMessageTitles.clear(); earlyRelayAcks.clear();
        setWrappedLabel(e2eeState, "X25519 + HKDF session active"); setWrappedLabel(pinState, "Ed25519 signature verified");
        sendButton.setEnabled(true); composer.setEnabled(true); composer.requestFocusInWindow();
        addActivity("E2EE", "Pinned identity verified; authenticated ephemeral X25519 key exchange completed with " + peer + ".");
        updateKeysOverview();
    }

    private void keyVersion(long version) {
        currentKeyVersion = version; setWrappedLabel(keyState, "Epoch " + version + " • refresh every 10 messages");
        setWrappedLabel(seqState, "Sequence " + (client == null ? "—" : "advancing") + " • duplicate/out-of-order rejected");
        addActivity("KEY", "Message key epoch advanced to " + version + ".");
        updateKeysOverview();
    }

    private void send() {
        String text = composer.getText().strip();
        if (text.isEmpty()) return;
        if (!authenticated || client == null) { setStatus("Connect before sending a message."); return; }
        composer.setText("");
        inputQueue.offer("/to " + currentPeer + " " + text);
    }

    private void addMessage(boolean outgoing, String plaintext, String envelope, long sequence, long version) {
        JPanel row = new JPanel(new BorderLayout()); row.setOpaque(false); row.setBorder(new EmptyBorder(4, 0, 4, 0));
        JPanel bubble = new JPanel(new BorderLayout(0, 5)); bubble.setBackground(outgoing ? new Color(216, 247, 198) : Color.WHITE);
        bubble.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(217, 226, 216)), new EmptyBorder(10, 12, 10, 12)));
        bubble.setMaximumSize(new Dimension(520, 500));
        String senderLabel = outgoing ? "You" : currentPeer;
        String sendState = outgoing && earlyRelayAcks.remove(sequence) ? "RELAY ROUTED" : (outgoing ? "PENDING" : "RECEIVED");
        JLabel title = new JLabel(senderLabel + "  •  " + sendState
                + "  •  seq " + sequence + "  •  key epoch " + version + "  •  " + LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm")));
        if (outgoing && "PENDING".equals(sendState)) pendingMessageTitles.put(sequence, title);
        if (outgoing) title.setToolTipText("Relay acknowledgement means the envelope was routed to the peer connection; it is not a read receipt.");
        title.setForeground(outgoing ? DEEP_GREEN : MUTED); title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); bubble.add(title, BorderLayout.NORTH);
        int logicalLines = Math.max(1, plaintext.split("\\R", -1).length);
        JTextArea body = new JTextArea(plaintext, Math.min(6, logicalLines), 38); body.setEditable(false); body.setLineWrap(true); body.setWrapStyleWord(true);
        body.setOpaque(false); body.setForeground(TEXT); body.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14)); body.setBorder(null); bubble.add(body, BorderLayout.CENTER);
        JPanel detail = new JPanel(new BorderLayout(0, 6)); detail.setOpaque(false);
        JLabel process = new JLabel(outgoing ? "Plaintext → AES-256-GCM → encrypted envelope sent" : "Encrypted envelope → tag + sequence verified → decrypted locally");
        process.setForeground(GREEN); process.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); detail.add(process, BorderLayout.NORTH);
        JTextArea cipher = new JTextArea(envelope); cipher.setEditable(false); cipher.setLineWrap(true); cipher.setWrapStyleWord(true);
        cipher.setRows(4); cipher.setBackground(new Color(244, 247, 245)); cipher.setForeground(new Color(55, 73, 76)); cipher.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        JScrollPane cipherScroll = new JScrollPane(cipher); cipherScroll.setPreferredSize(new Dimension(430, 95)); detail.add(cipherScroll, BorderLayout.CENTER);
        JLabel note = new JLabel(wrappedHtml("Envelope contains version, 96-bit nonce, ciphertext, and 128-bit GCM tag. Relay cannot decrypt it.", 64));
        note.setForeground(MUTED); note.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 9)); detail.add(note, BorderLayout.SOUTH);
        JToggleButton inspect = new JToggleButton("Show encrypted payload"); inspect.setFocusPainted(false); inspect.setBorderPainted(false);
        inspect.setContentAreaFilled(false); inspect.setHorizontalAlignment(JToggleButton.LEFT); inspect.setForeground(GREEN); inspect.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        detail.setVisible(false); inspect.addActionListener(event -> {
            detail.setVisible(inspect.isSelected());
            inspect.setText(inspect.isSelected() ? "Hide encrypted payload" : "Show encrypted payload");
            bubble.revalidate();
            Dimension updated = bubble.getPreferredSize();
            row.setMaximumSize(new Dimension(Integer.MAX_VALUE, updated.height + 8));
            messageList.revalidate(); messageList.repaint();
        });
        JPanel lower = new JPanel(new BorderLayout()); lower.setOpaque(false); lower.add(inspect, BorderLayout.NORTH); lower.add(detail, BorderLayout.CENTER); bubble.add(lower, BorderLayout.SOUTH);
        row.add(bubble, outgoing ? BorderLayout.EAST : BorderLayout.WEST);
        Dimension bubbleSize = bubble.getPreferredSize();
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, bubbleSize.height + 8));
        messageList.add(row); messageList.add(Box.createVerticalStrut(4));
        messageList.revalidate(); messageList.repaint();
        SwingUtilities.invokeLater(() -> { java.awt.Container parent = messageList.getParent(); if (parent instanceof javax.swing.JViewport viewport) viewport.setViewPosition(new java.awt.Point(0, messageList.getHeight())); });
        if (outgoing) { seqState.setText("Last sent sequence " + sequence + " • next key epoch at message " + (sequence / 10 * 10 + 1)); addActivity("MESSAGE", "Encrypted message prepared and sent; relay received only the envelope."); }
        else { seqState.setText("Accepted sequence " + sequence + " • replay guard advanced"); addActivity("VERIFY", "GCM authentication passed and sequence " + sequence + " was accepted before displaying plaintext."); }
    }

    private void markDelivered(long sequence) {
        JLabel title = pendingMessageTitles.remove(sequence);
        if (title == null) earlyRelayAcks.add(sequence);
        else title.setText(title.getText().replace("PENDING", "RELAY ROUTED"));
        addActivity("DELIVERY", "Relay routed sequence " + sequence + " to " + currentPeer + "'s active connection (not a read receipt).");
    }

    private void addActivity(String category, String text) {
        String line = LocalTime.now().format(CLOCK) + "  " + category + "  " + text;
        appendActivity(line);
    }

    private void refreshSecurityActivity() {
        try {
            List<SecurityEventLog.SecurityEvent> events = SecurityEventLog.readRecent();
            events.stream().skip(Math.max(0, events.size() - 12L)).forEach(event -> {
                String eventKey = event.timestamp() + "|" + event.type() + "|" + event.actor() + "|" + event.summary();
                if (seenAuditEvents.add(eventKey)) appendActivity(CLOCK.format(event.timestamp().atZone(java.time.ZoneId.systemDefault()).toLocalTime())
                        + "  " + event.severity() + "  " + event.type() + "  " + event.actor());
            });
        } catch (IOException exception) { activityList.setText("Could not read local security event log."); }
    }

    private void appendActivity(String line) {
        activityLines.addLast(line);
        while (activityLines.size() > 35) activityLines.removeFirst();
        activityList.setText(String.join("\n", activityLines));
        activityList.setCaretPosition(activityList.getDocument().getLength());
    }

    private void disconnected() {
        client = null;
        if (!authenticated) { connectButton.setEnabled(true); return; }
        authenticated = false; eventTimer.stop(); sendButton.setEnabled(false); composer.setEnabled(false);
        identityVerified = false; e2eeActive = false;
        currentLocalSessionId = null; currentPeerSessionId = null;
        currentKeyVersion = -1;
        setWrappedLabel(e2eeState, "Waiting for authenticated session");
        setWrappedLabel(keyState, "Key epoch: —");
        pendingMessageTitles.clear(); earlyRelayAcks.clear();
        connectionLabel.setText("DISCONNECTED"); connectionLabel.setForeground(new Color(175, 75, 71));
        setStatus("Disconnected. Close and reopen SecureConnect to reconnect with a new account session.");
        addActivity("SESSION", "TLS account session closed; end-to-end session keys are no longer available.");
        ((java.awt.CardLayout) cards.getLayout()).show(cards, "login");
        connectButton.setEnabled(true); updateKeysOverview();
    }

    private void setStatus(String message) {
        if (authenticated) { connectionLabel.setToolTipText(message); }
        else loginStatus.setText(message);
        if (authenticated && (message.contains("Peer offline") || message.contains("Peer key rejected"))) {
            e2eeActive = false;
            identityVerified = false;
            setWrappedLabel(pinState, "Peer signature: waiting for a fresh signed key exchange");
            setWrappedLabel(e2eeState, "Waiting for verified peer session"); setWrappedLabel(keyState, "Key epoch: —");
            sendButton.setEnabled(false); composer.setEnabled(false);
        }
        if (authenticated && (message.contains("rejected") || message.contains("failed") || message.contains("disconnected"))) addActivity("STATUS", message);
        updateKeysOverview();
    }

    private static void addSecurityRow(JPanel parent, String caption, JLabel value, Color accent) {
        JPanel box = new JPanel(new BorderLayout(0, 5)); box.setBackground(Color.WHITE);
        box.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(9, 10, 9, 10)));
        JLabel label = new JLabel(caption); label.setForeground(MUTED); label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 9));
        value.setForeground(accent); value.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        if (!value.getText().startsWith("<html>")) setWrappedLabel(value, value.getText());
        value.setMaximumSize(new Dimension(244, 40));
        box.add(label, BorderLayout.NORTH); box.add(value, BorderLayout.CENTER); box.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT); box.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        parent.add(box); addGap(parent, 6);
    }

    private static void addSecurityRow(JPanel parent, String caption, String value, Color accent) {
        addSecurityRow(parent, caption, body(value), accent);
    }

    private static JLabel heading(String value) { JLabel label = new JLabel(value); label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 26)); label.setForeground(TEXT); label.setAlignmentX(0f); return label; }
    private static JLabel body(String value) { JLabel label = new JLabel(wrappedHtml(value, 32)); label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); label.setForeground(MUTED); label.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT); return label; }
    private static void setWrappedLabel(JLabel label, String value) { label.setText(wrappedHtml(value, 31)); label.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT); }
    private static String wrappedHtml(String value, int maxCharacters) {
        StringBuilder html = new StringBuilder("<html>");
        int lineLength = 0;
        for (String word : htmlEscape(value).split("\\s+")) {
            if (lineLength > 0 && lineLength + word.length() + 1 > maxCharacters) {
                html.append("<br>"); lineLength = 0;
            } else if (lineLength > 0) {
                html.append(' '); lineLength++;
            }
            html.append(word); lineLength += word.length();
        }
        return html.append("</html>").toString();
    }
    private static String htmlEscape(String value) { return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"); }
    private static JLabel formLabel(String value) { JLabel label = new JLabel(value); label.setForeground(MUTED); label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); label.setAlignmentX(0f); return label; }
    private static void styleField(javax.swing.JComponent field) { field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38)); field.setAlignmentX(0f); field.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(7, 9, 7, 9))); }
    private static void addGap(JPanel panel, int height) { panel.add(Box.createRigidArea(new Dimension(1, height))); }
    private static int parsePort(String value) { try { int port = Integer.parseInt(value); if (port < 1 || port > 65535) throw new IllegalArgumentException("port must be between 1 and 65535"); return port; } catch (NumberFormatException exception) { throw new IllegalArgumentException("port must be a number"); } }
    private static String safeMessage(Exception exception) { return exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage(); }
    private void runOnUi(Runnable update) { SwingUtilities.invokeLater(update); }

    private final class Bridge implements ClientConsole.Interaction {
        private final String action;
        private char[] password;
        private char[] confirmation;
        private boolean confirmationRead;
        private Bridge(String action, char[] password, char[] confirmation) { this.action = action; this.password = password; this.confirmation = confirmation; }
        @Override public String readLine(String prompt) { return action; }
        @Override public synchronized char[] readPassword(String prompt) {
            char[] result;
            if (prompt.toLowerCase(java.util.Locale.ROOT).contains("confirm")) { result = confirmation; confirmation = new char[0]; confirmationRead = true; }
            else { result = password; password = new char[0]; }
            char[] copy = result.clone(); Arrays.fill(result, '\0'); return copy;
        }
        @Override public String readChatLine() throws IOException {
            try { return inputQueue.take(); }
            catch (InterruptedException exception) { Thread.currentThread().interrupt(); return null; }
        }
        @Override public void println(String message) { runOnUi(() -> { if (authenticated) addActivity("CLIENT", message); else loginStatus.setText(message); }); }
    }

    /** Small helper layout that centers the login card without external layout dependencies. */
    private static final class GridBagLayoutCompat extends java.awt.GridBagLayout { }
}
