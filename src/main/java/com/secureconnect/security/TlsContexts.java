package com.secureconnect.security;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/** Builds TLS contexts from local PKCS#12 keystore/truststore configuration. */
public final class TlsContexts {
    private TlsContexts() {
    }

    public static SSLContext serverContextFromEnvironment() throws IOException {
        String file = required("SECURECONNECT_TLS_KEYSTORE");
        char[] password = required("SECURECONNECT_TLS_KEYSTORE_PASSWORD").toCharArray();
        try (InputStream input = Files.newInputStream(Path.of(file))) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(input, password);
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), null, null);
            return context;
        } catch (GeneralSecurityException exception) {
            throw new IOException("could not initialize the TLS server identity from the PKCS#12 keystore", exception);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    public static SSLContext clientContextFromEnvironment() throws IOException {
        String file = required("SECURECONNECT_TLS_TRUSTSTORE");
        char[] password = required("SECURECONNECT_TLS_TRUSTSTORE_PASSWORD").toCharArray();
        try (InputStream input = Files.newInputStream(Path.of(file))) {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(input, password);
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException exception) {
            throw new IOException("could not initialize TLS trust from the PKCS#12 truststore", exception);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("set environment variable " + name + " before starting SecureConnect");
        }
        return value;
    }
}
