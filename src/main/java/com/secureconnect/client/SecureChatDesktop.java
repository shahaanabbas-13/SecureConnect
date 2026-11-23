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
import java.nio.file.Files;
import java.security.PublicKey;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Set;
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
    private final ArrayDeque<String> activityLines = new ArrayDeque<>();
    private final Set<String> seenAuditEvents = new HashSet<>();
    private final BlockingQueue<String> inputQueue = new LinkedBlockingQueue<>();
    private volatile ChatClient client;
    private volatile boolean authenticated;
    private volatile String currentUsername;
    private volatile String currentPeer;
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
            }
            @Override public void windowClosed(WindowEvent event) { eventTimer.stop(); }
        });
        ((java.awt.CardLayout) cards.getLayout()).show(cards, "login");
        frame.setVisible(true);
        usernameField.setText(initialUsername);
        peerField.setText(initialPeer);
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
        center.add(conversationScroll, BorderLayout.CENTER);
        JPanel inputArea = new JPanel(new BorderLayout(10, 0)); inputArea.setBackground(new Color(242, 245, 242)); inputArea.setBorder(new EmptyBorder(12, 16, 12, 16));
        composer.setLineWrap(true); composer.setWrapStyleWord(true); composer.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14)); composer.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(9, 12, 9, 12)));
        JScrollPane composerScroll = new JScrollPane(composer); composerScroll.setBorder(null); inputArea.add(composerScroll, BorderLayout.CENTER);
        sendButton.setForeground(Color.WHITE); sendButton.setBackground(GREEN); sendButton.setFocusPainted(false); sendButton.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        sendButton.addActionListener(event -> send()); inputArea.add(sendButton, BorderLayout.EAST); center.add(inputArea, BorderLayout.SOUTH);

        JPanel right = new JPanel(new BorderLayout(0, 12)); right.setBackground(SIDEBAR); right.setPreferredSize(new Dimension(300, 0));
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
        flowTitle.setBorder(new EmptyBorder(18, 0, 8, 0)); security.add(flowTitle);
        security.add(body("1  Compose plaintext on sender device")); addGap(security, 6);
        security.add(body("2  AES-256-GCM seals it with a fresh nonce")); addGap(security, 6);
        security.add(body("3  Relay routes opaque encrypted envelope")); addGap(security, 6);
        security.add(body("4  Receiver checks sequence + GCM tag")); addGap(security, 6);
        security.add(body("5  Plaintext appears only after verification")); addGap(security, 6);
        security.add(body("Key epochs derive from the session root every 10 messages; this demo does not implement a forward-secure ratchet."));
        JLabel activityTitle = new JLabel("LIVE SECURITY ACTIVITY"); activityTitle.setForeground(GREEN); activityTitle.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        activityTitle.setBorder(new EmptyBorder(18, 0, 6, 0)); security.add(activityTitle);
        activityList.setEditable(false); activityList.setLineWrap(true); activityList.setWrapStyleWord(true); activityList.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        activityList.setBackground(new Color(241, 246, 243)); activityList.setForeground(TEXT); activityList.setBorder(new EmptyBorder(8, 8, 8, 8));
        JScrollPane eventScroll = new JScrollPane(activityList); eventScroll.setPreferredSize(new Dimension(250, 150)); eventScroll.setBorder(BorderFactory.createLineBorder(LINE)); security.add(eventScroll);
        JScrollPane rightScroll = new JScrollPane(security); rightScroll.setBorder(null); rightScroll.getViewport().setBackground(SIDEBAR); right.add(rightScroll, BorderLayout.CENTER);
        root.add(left, BorderLayout.WEST); root.add(center, BorderLayout.CENTER); root.add(right, BorderLayout.EAST);
        sendButton.setEnabled(false); composer.setEnabled(false);
        return root;
    }

    private void connect() {
        if (client != null) return;
        String username = usernameField.getText().trim(); String peer = peerField.getText().trim();
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
            @Override public void onSessionReady(String name) { runOnUi(() -> sessionReady(name)); }
            @Override public void onKeyVersion(long version) { runOnUi(() -> keyVersion(version)); }
            @Override public void onOutgoing(String text, String envelope, long sequence, long version) { runOnUi(() -> addMessage(true, text, envelope, sequence, version)); }
            @Override public void onDelivered(String name, long sequence) { runOnUi(() -> markDelivered(sequence)); }
            @Override public void onIncoming(String sender, String text, String envelope, long sequence, long version) { runOnUi(() -> addMessage(false, text, envelope, sequence, version)); }
            @Override public void onSecurity(String message) { runOnUi(() -> addActivity("SECURITY", message)); }
            @Override public void onDisconnected() { runOnUi(() -> disconnected()); }
        };
        Thread thread = new Thread(() -> {
            try {
                ChatClient chatClient = new ChatClient(host, port, username, peer,
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
        ((java.awt.CardLayout) cards.getLayout()).show(cards, "chat");
        peerHeader.setText(peer); connectionLabel.setText("ONLINE  •  ACCOUNT AUTHENTICATED"); connectionLabel.setForeground(GREEN);
        setStatus("TLS connection authenticated as " + username + ". Waiting for " + peer + " to establish an E2EE session.");
        sendButton.setEnabled(false); composer.setEnabled(false); eventTimer.start(); refreshSecurityActivity();
        addActivity("TLS", "Account authentication succeeded; connection-bound session active.");
    }

    private void sessionReady(String peer) {
        e2eeState.setText("X25519 + HKDF session active"); pinState.setText("Ed25519 signature verified");
        sendButton.setEnabled(true); composer.setEnabled(true); composer.requestFocusInWindow();
        addActivity("E2EE", "Pinned identity verified; authenticated ephemeral X25519 key exchange completed with " + peer + ".");
    }

    private void keyVersion(long version) {
        currentKeyVersion = version; keyState.setText("Epoch " + version + " • refresh every 10 messages");
        seqState.setText("Sequence " + (client == null ? "—" : "advancing") + " • duplicate/out-of-order rejected");
        addActivity("KEY", "Message key epoch advanced to " + version + ".");
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
        JPanel bubble = new JPanel(new BorderLayout(0, 7)); bubble.setBackground(outgoing ? new Color(216, 247, 198) : Color.WHITE);
        bubble.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(217, 226, 216)), new EmptyBorder(10, 12, 10, 12)));
        bubble.setMaximumSize(new Dimension(520, 500));
        JLabel title = new JLabel((outgoing ? "You" : currentPeer) + "  •  " + (outgoing ? "SENT" : "RECEIVED")
                + "  •  seq " + sequence + "  •  key epoch " + version);
        title.setForeground(outgoing ? DEEP_GREEN : MUTED); title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); bubble.add(title, BorderLayout.NORTH);
        JTextArea body = new JTextArea(plaintext); body.setEditable(false); body.setLineWrap(true); body.setWrapStyleWord(true);
        body.setOpaque(false); body.setForeground(TEXT); body.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 14)); body.setBorder(null); bubble.add(body, BorderLayout.CENTER);
        JPanel detail = new JPanel(new BorderLayout(0, 6)); detail.setOpaque(false);
        JLabel process = new JLabel(outgoing ? "Plaintext → AES-256-GCM → encrypted envelope sent" : "Encrypted envelope → tag + sequence verified → decrypted locally");
        process.setForeground(GREEN); process.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)); detail.add(process, BorderLayout.NORTH);
        JTextArea cipher = new JTextArea(envelope); cipher.setEditable(false); cipher.setLineWrap(true); cipher.setWrapStyleWord(true);
        cipher.setRows(4); cipher.setBackground(new Color(244, 247, 245)); cipher.setForeground(new Color(55, 73, 76)); cipher.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        JScrollPane cipherScroll = new JScrollPane(cipher); cipherScroll.setPreferredSize(new Dimension(430, 95)); detail.add(cipherScroll, BorderLayout.CENTER);
        JLabel note = new JLabel("Envelope contains version, 96-bit nonce, ciphertext, and 128-bit GCM tag. Relay cannot decrypt it.");
        note.setForeground(MUTED); note.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 9)); detail.add(note, BorderLayout.SOUTH);
        JToggleButton inspect = new JToggleButton("Show encrypted payload"); inspect.setFocusPainted(false); inspect.setBorderPainted(false);
        inspect.setContentAreaFilled(false); inspect.setHorizontalAlignment(JToggleButton.LEFT); inspect.setForeground(GREEN); inspect.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10));
        detail.setVisible(false); inspect.addActionListener(event -> { detail.setVisible(inspect.isSelected()); inspect.setText(inspect.isSelected() ? "Hide encrypted payload" : "Show encrypted payload"); bubble.revalidate(); bubble.repaint(); });
        JPanel lower = new JPanel(new BorderLayout()); lower.setOpaque(false); lower.add(inspect, BorderLayout.NORTH); lower.add(detail, BorderLayout.CENTER); bubble.add(lower, BorderLayout.SOUTH);
        row.add(bubble, outgoing ? BorderLayout.EAST : BorderLayout.WEST); messageList.add(row); messageList.add(Box.createVerticalStrut(4));
        messageList.revalidate(); messageList.repaint();
        SwingUtilities.invokeLater(() -> { java.awt.Container parent = messageList.getParent(); if (parent instanceof javax.swing.JViewport viewport) viewport.setViewPosition(new java.awt.Point(0, messageList.getHeight())); });
        if (outgoing) { seqState.setText("Last sent sequence " + sequence + " • next key epoch at message " + (sequence / 10 * 10 + 1)); addActivity("MESSAGE", "Encrypted message prepared and sent; relay received only the envelope."); }
        else { seqState.setText("Accepted sequence " + sequence + " • replay guard advanced"); addActivity("VERIFY", "GCM authentication passed and sequence " + sequence + " was accepted before displaying plaintext."); }
    }

    private void markDelivered(long sequence) { addActivity("DELIVERY", "Relay acknowledged delivery to " + currentPeer + " (latest sequence " + sequence + ")."); }

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
        if (!authenticated) { client = null; connectButton.setEnabled(true); return; }
        authenticated = false; eventTimer.stop(); sendButton.setEnabled(false); composer.setEnabled(false);
        connectionLabel.setText("DISCONNECTED"); connectionLabel.setForeground(new Color(175, 75, 71));
        setStatus("Disconnected. Close and reopen SecureConnect to reconnect with a new account session.");
        addActivity("SESSION", "TLS account session closed; end-to-end session keys are no longer available.");
    }

    private void setStatus(String message) {
        if (authenticated) { connectionLabel.setToolTipText(message); }
        else loginStatus.setText(message);
        if (authenticated && (message.contains("Peer offline") || message.contains("Peer key rejected"))) {
            e2eeState.setText("Waiting for verified peer session"); keyState.setText("Key epoch: —");
            sendButton.setEnabled(false); composer.setEnabled(false);
        }
        if (authenticated && (message.contains("rejected") || message.contains("failed") || message.contains("disconnected"))) addActivity("STATUS", message);
    }

    private static void addSecurityRow(JPanel parent, String caption, JLabel value, Color accent) {
        JPanel box = new JPanel(new BorderLayout(0, 5)); box.setBackground(Color.WHITE);
        box.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(LINE), new EmptyBorder(9, 10, 9, 10)));
        JLabel label = new JLabel(caption); label.setForeground(MUTED); label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 9));
        value.setForeground(accent); value.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 11));
        box.add(label, BorderLayout.NORTH); box.add(value, BorderLayout.CENTER); box.setMaximumSize(new Dimension(Integer.MAX_VALUE, 56));
        parent.add(box); addGap(parent, 6);
    }

    private static void addSecurityRow(JPanel parent, String caption, String value, Color accent) {
        addSecurityRow(parent, caption, body(value), accent);
    }

    private static JLabel heading(String value) { JLabel label = new JLabel(value); label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 26)); label.setForeground(TEXT); label.setAlignmentX(0f); return label; }
    private static JLabel body(String value) { JLabel label = new JLabel("<html>" + value + "</html>"); label.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12)); label.setForeground(MUTED); label.setAlignmentX(0f); return label; }
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
