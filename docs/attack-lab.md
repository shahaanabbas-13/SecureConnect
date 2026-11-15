# SecureConnect controlled attack lab

This lab runs only against the local SecureConnect relay. The attack proxy binds to `127.0.0.1` and refuses non-loopback targets. Use dummy messages and stop any clients that connect directly to the relay before starting a scenario.

## Prerequisites

Build the project and generate Alice/Bob identity keys once if they do not already exist:

```powershell
mvn package
java -cp target/classes com.secureconnect.Main identity-keygen Alice
java -cp target/classes com.secureconnect.Main identity-keygen Bob
```

Compare the printed SHA-256 fingerprints through a trusted channel. Keep both private key files local. For each scenario, use four PowerShell terminals from the project folder:

1. Start the relay on its default port:

   ```powershell
   java -cp target/classes com.secureconnect.Main server
   ```

2. Start one proxy mode in terminal 2. The proxy listens on port 5051 and forwards to the relay on 5050. Use only one proxy mode at a time:

   ```powershell
   java -cp target/classes com.secureconnect.Main attack-proxy eavesdrop
   ```

3. Connect Bob through the proxy in terminal 3:

   ```powershell
   $env:SECURECONNECT_TRUSTED_PEER_KEY = (Get-Content .\keys\Alice.ed25519.public -Raw).Trim()
   java -cp target/classes com.secureconnect.Main client Bob Alice 127.0.0.1 5051
   ```

4. Connect Alice through the proxy in terminal 4:

   ```powershell
   $env:SECURECONNECT_TRUSTED_PEER_KEY = (Get-Content .\keys\Bob.ed25519.public -Raw).Trim()
   java -cp target/classes com.secureconnect.Main client Alice Bob 127.0.0.1 5051
   ```

Wait for the authenticated-session message before sending. Alice sends with `/to Bob <dummy message>`. Stop both clients with `/quit` and stop the proxy with Ctrl+C before repeating with a different mode. The relay can stay running.

## Scenarios

| Proxy mode | Action | Expected observation |
|---|---|---|
| `eavesdrop` | Reads outgoing message frames and reports their sequence, key version, and encoded size. | The proxy reports that no plaintext was observed; Bob still receives the decrypted message. |
| `tamper` | Flips one ciphertext bit in the first outgoing message. | Bob rejects it because the AES-GCM authentication tag no longer verifies. |
| `replay` | Forwards the first outgoing message twice with the same sequence. | Bob displays the original once and rejects the duplicate sequence. The relay itself still forwards both copies. |
| `key-substitution` | Changes the first signed ephemeral-key announcement. | The peer that receives the changed announcement rejects its signature against the pinned Ed25519 identity key. |

To run another scenario, restart terminal 2 with its mode, then reconnect both clients through port 5051 so each run uses a fresh key exchange and message sequence.

## What this demonstrates and what it does not

These are controlled demonstrations of client-side E2EE checks. Eavesdropping shows that the relay path carries an encrypted envelope; tampering and replay show receiver-side rejection; key substitution shows identity-signature verification. The current relay has no TLS, account authentication, persistence, or server-side duplicate tracking. The key-substitution demonstration can leave one client reporting a verified peer while the other rejects it; the prototype does not implement a mutual key-confirmation protocol. The attack proxy and console messages are educational tools, not an IDS or production threat-detection system.
