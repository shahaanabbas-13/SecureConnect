# SecureConnect controlled attack lab

The lab operates against a local relay only. Proxy modes bind to `127.0.0.1` and refuse non-loopback targets. The `dos` mode makes exactly 20 bounded TLS connection/request attempts. Use dummy accounts and messages.

## Prepare the TLS environment

Follow [the README TLS setup](../README.md#prepare-local-tls-for-phase-5) once to create the local certificate and truststore. For each PowerShell window, set its environment variables from the project folder:

- Relay: `SECURECONNECT_TLS_KEYSTORE` and `SECURECONNECT_TLS_KEYSTORE_PASSWORD`.
- Client: `SECURECONNECT_TLS_TRUSTSTORE` and `SECURECONNECT_TLS_TRUSTSTORE_PASSWORD`.
- Attack proxy: both sets, because it accepts client TLS and opens a separate trusted TLS connection to the relay.

The proxy presents the same local certificate as the relay and trusts the relay certificate. This lets the lab inspect or modify application frames after TLS termination. It models a trusted or compromised TLS endpoint; a normal untrusted network proxy would fail certificate validation. Credentials are not logged by the proxy. TLS does not expose end-to-end message plaintext because only Alice and Bob hold the E2EE session key.

## Start a scenario

Build and create Alice and Bob's identity keys once if needed:

```powershell
mvn package
java -jar target/secureconnect-1.0-SNAPSHOT.jar identity-keygen Alice
java -jar target/secureconnect-1.0-SNAPSHOT.jar identity-keygen Bob
```

Compare the printed SHA-256 fingerprints through a trusted channel. Use four PowerShell terminals in the project folder:

1. In terminal 1, set the relay TLS keystore variables, then start the relay:

   ```powershell
   $env:SECURECONNECT_TLS_KEYSTORE = (Resolve-Path .\certs\server.p12).Path
   $env:SECURECONNECT_TLS_KEYSTORE_PASSWORD = '<server keystore password>'
   java -jar target/secureconnect-1.0-SNAPSHOT.jar server
   ```

2. In terminal 2, set both the proxy keystore and upstream truststore variables, then start one mode:

   ```powershell
   $env:SECURECONNECT_TLS_KEYSTORE = (Resolve-Path .\certs\server.p12).Path
   $env:SECURECONNECT_TLS_KEYSTORE_PASSWORD = '<server keystore password>'
   $env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
   $env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
   java -jar target/secureconnect-1.0-SNAPSHOT.jar attack-proxy eavesdrop
   ```

3. In terminal 3, set the client truststore variables and Bob's pinned Alice identity key:

   ```powershell
   $env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
   $env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
   $env:SECURECONNECT_TRUSTED_PEER_KEY = (Get-Content .\keys\Alice.ed25519.public -Raw).Trim()
   java -jar target/secureconnect-1.0-SNAPSHOT.jar client Bob Alice 127.0.0.1 5051
   ```

4. In terminal 4, set the same truststore variables and Alice's pinned Bob identity key:

   ```powershell
   $env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
   $env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
   $env:SECURECONNECT_TRUSTED_PEER_KEY = (Get-Content .\keys\Bob.ed25519.public -Raw).Trim()
   java -jar target/secureconnect-1.0-SNAPSHOT.jar client Alice Bob 127.0.0.1 5051
   ```

Choose `register` for each account the first time; choose `login` on later runs. Account passwords need at least 12 characters. Stop clients with `/logout`, then stop the proxy with Ctrl+C before changing modes. Keep both TLS environment settings in the proxy terminal for each run.

## Scenarios

| Mode | Action | Expected observation |
|---|---|---|
| `eavesdrop` | Reads outgoing `SEND` frames and reports sequence, key version, and encoded size. | The proxy sees metadata and ciphertext, not message plaintext. |
| `tamper` | Flips one bit in the first outgoing encrypted envelope. | Bob rejects it because the AES-GCM authentication tag fails. |
| `replay` | Forwards the first outgoing message twice using the same sequence number. | Bob accepts the first and rejects the duplicate/out-of-order sequence. |
| `key-substitution` | Changes the first signed ephemeral-key announcement. | The recipient rejects the signature against its pinned Ed25519 identity key. |
| `masquerade` | Rewrites a Mallory login name to Alice. | The relay rejects it because Mallory does not know Alice's password; no authenticated Alice session is created. |
| `dos` | Opens 20 short-lived TLS connections and submits malformed authentication requests. | Reports how many requests the relay handled. This is a bounded baseline, not a DoS mitigation claim. |

For the masquerade scenario, stop Alice's legitimate client, create a Mallory identity if needed, start the proxy in `masquerade` mode, connect Bob as above, then try Mallory with Bob's key pinned:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar identity-keygen Mallory
$env:SECURECONNECT_TRUSTED_PEER_KEY = (Get-Content .\keys\Bob.ed25519.public -Raw).Trim()
java -jar target/secureconnect-1.0-SNAPSHOT.jar client Mallory Bob 127.0.0.1 5051
```

Select `register` or `login` for Mallory. The proxy rewrites only the claimed username on login; the relay checks the password against Alice's verifier, so authentication fails. Do not register Mallory as Alice.

## Limits

The proxy and console logs are teaching aids, not an intrusion-detection system. Login throttling is per username and in memory, so it resets when the relay restarts and does not coordinate across server processes. The account file contains Argon2id verifiers and is not encrypted at rest. The TLS certificate is a locally trusted self-signed certificate. This is not a production deployment or a formal security proof.
