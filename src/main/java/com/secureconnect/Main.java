package com.secureconnect;

import com.secureconnect.client.ChatClient;
import com.secureconnect.attacks.AttackProxy;
import com.secureconnect.keymanagement.IdentityKeys;
import com.secureconnect.server.RelayServer;

import java.io.IOException;

public final class Main {
    private static final int DEFAULT_PORT = 5050;

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length == 0 || "help".equalsIgnoreCase(args[0])) {
            printUsage();
            return;
        }

        try {
            switch (args[0].toLowerCase()) {
                case "server" -> runServer(args);
                case "client" -> runClient(args);
                case "identity-keygen" -> runIdentityKeygen(args);
                case "attack-proxy" -> runAttackProxy(args);
                default -> printUsage();
            }
        } catch (IllegalArgumentException exception) {
            System.err.println("Error: " + exception.getMessage());
            printUsage();
            System.exit(2);
        } catch (IOException exception) {
            System.err.println("SecureConnect could not start: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void runServer(String[] args) throws IOException {
        if (args.length > 2) {
            throw new IllegalArgumentException("server accepts only an optional port");
        }
        int port = args.length == 2 ? parsePort(args[1]) : DEFAULT_PORT;
        new RelayServer(port).start();
    }

    private static void runClient(String[] args) throws IOException {
        if (args.length < 3 || args.length > 5) {
            throw new IllegalArgumentException("client requires a username, peer username, and optional host/port");
        }
        String username = args[1];
        String peerUsername = args[2];
        String host = args.length >= 4 ? args[3] : "127.0.0.1";
        int port = args.length == 5 ? parsePort(args[4]) : DEFAULT_PORT;
        String encodedTrustedKey = System.getenv("SECURECONNECT_TRUSTED_PEER_KEY");
        if (encodedTrustedKey == null || encodedTrustedKey.isBlank()) {
            throw new IllegalArgumentException("set SECURECONNECT_TRUSTED_PEER_KEY to the verified peer identity public key");
        }
        new ChatClient(host, port, username, peerUsername,
                IdentityKeys.loadPrivate(username),
                IdentityKeys.decodePinnedPublicKey(encodedTrustedKey)).run();
    }

    private static void runIdentityKeygen(String[] args) throws IOException {
        if (args.length != 2) {
            throw new IllegalArgumentException("identity-keygen requires a username");
        }
        String publicKey = IdentityKeys.generate(args[1]);
        System.out.println("Generated Ed25519 identity for " + args[1] + ".");
        System.out.println("Private key file: " + IdentityKeys.privatePath(args[1]).toAbsolutePath());
        System.out.println("Public key file:  " + IdentityKeys.publicPath(args[1]).toAbsolutePath());
        System.out.println("Identity public key (send to the peer over a trusted channel):");
        System.out.println(publicKey);
        System.out.println("SHA-256 fingerprint (compare with the peer out of band):");
        System.out.println(IdentityKeys.fingerprint(publicKey));
    }

    private static void runAttackProxy(String[] args) throws IOException {
        if (args.length < 2 || args.length > 5) {
            throw new IllegalArgumentException("attack-proxy requires a mode and optional listen/target settings");
        }
        AttackProxy.Mode mode = AttackProxy.Mode.parse(args[1]);
        int listenPort = args.length >= 3 ? parsePort(args[2]) : 5051;
        String targetHost = args.length >= 4 ? args[3] : "127.0.0.1";
        int targetPort = args.length == 5 ? parsePort(args[4]) : DEFAULT_PORT;
        new AttackProxy(mode, listenPort, targetHost, targetPort).start();
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("port must be between 1 and 65535");
            }
            return port;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("port must be a number");
        }
    }

    private static void printUsage() {
        System.out.println("SecureConnect — local encrypted messaging prototype");
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println();
        System.out.println("Start relay:  java -cp target/classes com.secureconnect.Main server [port]");
        System.out.println("Start client: java -cp target/classes com.secureconnect.Main client <username> <peer> [host] [port]");
        System.out.println("Generate identity: java -cp target/classes com.secureconnect.Main identity-keygen <username>");
        System.out.println("Attack proxy: java -cp target/classes com.secureconnect.Main attack-proxy <eavesdrop|tamper|replay|key-substitution> [listenPort] [targetHost] [targetPort]");
        System.out.println("Default port: " + DEFAULT_PORT + "; default client host: 127.0.0.1");
        System.out.println("X25519 + HKDF establish session keys; Ed25519 identity keys authenticate key shares.");
        System.out.println("Trust keys must be verified out of band. Use localhost only; this is an educational protocol.");
    }
}
