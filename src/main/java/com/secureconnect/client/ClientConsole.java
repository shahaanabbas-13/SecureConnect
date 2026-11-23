package com.secureconnect.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/** Reuses one input reader and masks passwords where the terminal supports it. */
public final class ClientConsole {
    public interface Interaction {
        String readLine(String prompt) throws IOException;
        char[] readPassword(String prompt) throws IOException;
        String readChatLine() throws IOException;
        void println(String message);
    }

    private final java.io.Console console = System.console();
    private final BufferedReader reader = console == null
            ? new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)) : null;
    private final PrintWriter output = new PrintWriter(System.out, true);
    private boolean warnedAboutEcho;
    private final Interaction interaction;

    public ClientConsole() { this(null); }

    public ClientConsole(Interaction interaction) { this.interaction = interaction; }

    public String readLine(String prompt) throws IOException {
        if (interaction != null) return interaction.readLine(prompt);
        if (console != null) return console.readLine("%s", prompt);
        output.print(prompt);
        output.flush();
        return reader.readLine();
    }

    public char[] readPassword(String prompt) throws IOException {
        if (interaction != null) return interaction.readPassword(prompt);
        if (console != null) return console.readPassword("%s", prompt);
        if (!warnedAboutEcho) {
            output.println("This terminal cannot mask password input; use a temporary demo password.");
            warnedAboutEcho = true;
        }
        String value = readLine(prompt);
        return value == null ? null : value.toCharArray();
    }

    public String readChatLine() throws IOException {
        if (interaction != null) return interaction.readChatLine();
        return console != null ? console.readLine() : reader.readLine();
    }

    public void println(String message) {
        if (interaction != null) interaction.println(message);
        else output.println(message);
    }
}
