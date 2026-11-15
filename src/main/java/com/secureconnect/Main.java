package com.secureconnect;

import com.secureconnect.client.ChatClient;
import com.secureconnect.crypto.AesGcmCrypto;
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
                case "keygen" -> runKeygen(args);
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
        if (args.length < 2 || args.length > 4) {
            throw new IllegalArgumentException("client requires a username and optional host/port");
        }
        String username = args[1];
        String host = args.length >= 3 ? args[2] : "127.0.0.1";
        int port = args.length == 4 ? parsePort(args[3]) : DEFAULT_PORT;
        String encodedKey = System.getenv("SECURECONNECT_DEMO_KEY");
        if (encodedKey == null || encodedKey.isBlank()) {
            throw new IllegalArgumentException("set SECURECONNECT_DEMO_KEY to the same generated key in both client terminals");
        }
        new ChatClient(host, port, username, AesGcmCrypto.decodeKey(encodedKey)).run();
    }

    private static void runKeygen(String[] args) {
        if (args.length != 1) {
            throw new IllegalArgumentException("keygen does not accept arguments");
        }
        System.out.println("Temporary AES-256 demo key (keep it out of the relay terminal):");
        System.out.println(AesGcmCrypto.generateKey());
        System.out.println("Copy the same value into SECURECONNECT_DEMO_KEY in both client terminals.");
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
        System.out.println("SecureConnect — local plaintext messaging prototype");
        System.out.println("Java: " + System.getProperty("java.version"));
        System.out.println();
        System.out.println("Start relay:  java -cp target/classes com.secureconnect.Main server [port]");
        System.out.println("Start client: java -cp target/classes com.secureconnect.Main client <username> [host] [port]");
        System.out.println("Generate key: java -cp target/classes com.secureconnect.Main keygen");
        System.out.println("Default port: " + DEFAULT_PORT + "; default client host: 127.0.0.1");
        System.out.println("AES-GCM encrypts message content; manually sharing this demo key is not key exchange.");
        System.out.println("Use only on localhost with dummy messages; this is not a production protocol.");
    }
}
