# SecureConnect

SecureConnect is an educational Java messaging project for studying end-to-end encryption, authenticated key establishment, replay protection, controlled attack simulations, and their performance costs.

## Current milestone: Account and transport security

The Java 21 prototype establishes an encrypted session between two console clients. Ed25519 identity keys sign ephemeral X25519 public keys; clients verify a pinned peer identity, then use HKDF-SHA-256 to derive AES-256-GCM session keys. TLS protects the client-to-relay connection. Accounts use Argon2id password verifiers; authenticated sessions belong to one TLS connection and expire after 30 minutes total or 10 minutes idle. The local relay forwards signed key announcements and encrypted message envelopes but never receives the end-to-end session key or message plaintext.

### Verify the Windows development environment

Open PowerShell in this folder and run:

```powershell
java -version
javac -version
$env:JAVA_HOME
mvn -version
code --version
```

Expected versions are Java/Javac 21, Maven 3.x, and VS Code. `mvn -version` should report that it is using the Java 21 runtime. If `JAVA_HOME` is empty, set it for the current PowerShell window to the installed JDK directory before running Maven:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Eclipse Adoptium\jdk-21.0.13.9-hotspot'
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
```

The exact JDK directory can vary by installation; use the directory containing `bin\java.exe`. After installation verification, the project can be opened in VS Code with `code .`.

## Architecture direction

Alice's and Bob's Java clients own their private keys and perform encryption, authentication-tag verification, and decryption locally. A Java relay server routes and stores ciphertext plus the minimum delivery metadata; it must not receive plaintext or end-to-end message keys. Transport protection (TLS) protects each client-to-server connection but does not replace end-to-end encryption. Authentication and authorization protect accounts and message access; signed identity/key information is needed to prevent public-key substitution during key establishment.

The supplied sketches include both an end-to-end encrypted relay and diagrams with a server/database. We use the relay model: backend persistence is permitted for ciphertext and metadata only. The system will not claim that public-key encryption alone provides sender identity, or that X25519 alone authenticates a key exchange.

## Prepare local TLS for Phase 5

The relay and client now require TLS configuration. For this localhost demonstration, create a self-signed certificate whose names match `localhost` and `127.0.0.1`, then trust that certificate in the client truststore. Run these commands once from the project folder. `keytool` will prompt you for passwords; remember the keystore and truststore passwords for the environment setup below.

```powershell
New-Item -ItemType Directory -Force .\certs | Out-Null
keytool -genkeypair -alias secureconnect-local -keyalg RSA -keysize 3072 -storetype PKCS12 `
  -keystore .\certs\server.p12 -validity 365 -dname "CN=localhost" `
  -ext "SAN=dns:localhost,ip:127.0.0.1"
keytool -exportcert -alias secureconnect-local -keystore .\certs\server.p12 `
  -file .\certs\server.cer
keytool -importcert -noprompt -alias secureconnect-local -file .\certs\server.cer `
  -keystore .\certs\client-truststore.p12 -storetype PKCS12
```

Set the TLS settings in each PowerShell terminal. The relay terminal needs the server keystore settings:

```powershell
$env:SECURECONNECT_TLS_KEYSTORE = (Resolve-Path .\certs\server.p12).Path
$env:SECURECONNECT_TLS_KEYSTORE_PASSWORD = '<server keystore password>'
```

Each client terminal needs the client truststore settings:

```powershell
$env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
$env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
```

These environment variables apply only to the current PowerShell window. The self-signed certificate is for local development, not a public service.

## Run the local encrypted messaging demonstration

Build the project:

```powershell
mvn package
```

Generate one identity for each user from the project folder:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar identity-keygen Alice
java -jar target/secureconnect-1.0-SNAPSHOT.jar identity-keygen Bob
```

Each command creates private/public files under `keys\` and prints the public identity key and its SHA-256 fingerprint. Keep private files local, exchange public keys, and compare fingerprints over a trusted channel. Alice must pin Bob's public key, and Bob must pin Alice's.

Create the Alice and Bob account records by selecting `register` the first time each identity logs in; choose passwords of at least 12 characters. Later connections select `login`. The account password is separate from each user's Ed25519 identity key. Account verifiers are stored in ignored local file `data\accounts.properties`.

Open three PowerShell terminals in the project folder. In terminal 1, set the server keystore environment variables above and start the relay:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar server
```

In terminals 2 and 3, set the client truststore environment variables above. In terminal 2, set Alice's verified public identity key and connect Bob:

```powershell
$env:SECURECONNECT_TRUSTED_PEER_KEY = '<Alice public key from identity-keygen>'
java -jar target/secureconnect-1.0-SNAPSHOT.jar client Bob Alice
```

In terminal 3, set Bob's verified public identity key and connect Alice:

```powershell
$env:SECURECONNECT_TRUSTED_PEER_KEY = '<Bob public key from identity-keygen>'
java -jar target/secureconnect-1.0-SNAPSHOT.jar client Alice Bob
```

After each client reports an authenticated encrypted session, Alice can type `/to Bob Hello Bob!`. Bob sees the decrypted message; Alice sees a delivery confirmation. Type `/logout` (or `/quit`) in each client, then press Ctrl+C in the relay terminal to stop the server. Usernames can contain 1–32 letters, digits, underscores, or hyphens. The relay defaults to port 5050 and binds only to `127.0.0.1`. Passwords are hidden when launched from a terminal with `System.console()`; some IDE consoles do not support hidden input.

Private identity files are Base64-encoded PKCS#8 data, not encrypted at rest. The `.gitignore` excludes `keys\`, certificate stores, and account records; do not commit or share private files. Account records contain salted Argon2id verifiers, not plaintext passwords. Verify public identity keys out of band; an unverified key copied through the relay allows key substitution. Replay sequence state and login throttling state are in memory and reset when the relay restarts. Epoch keys are deterministically derived from the session root, which remains in memory so it can derive later epochs; this is key refresh for demonstration, not a forward-secure ratchet. Use localhost and dummy messages only.

## Planned implementation sequence

1. **Foundation (complete):** verify Java/Maven/VS Code, keep the Maven build reproducible, and document architecture boundaries.
2. **Plaintext messaging baseline (complete):** local two-user messaging through a Java socket relay.
3. **AES-256-GCM (complete):** encrypt and decrypt on clients, carry a nonce, ciphertext, and tag, bind sender/recipient routing context as associated data, and reject authentication failures.
4. **Authenticated key establishment (prototype complete):** signed ephemeral X25519 public keys, pinned Ed25519 identities, and HKDF-SHA-256 session keys.
5. **Replay and key lifecycle (prototype complete):** authenticated per-direction sequence numbers reject duplicate/out-of-order messages; HKDF derives a new AES key epoch every 10 messages.
6. **Controlled attack experiments (prototype):** the localhost lab demonstrates eavesdropping, tampering, replay, signed-key substitution, a spoofed username, and a bounded 20-connection burst.
7. **Authentication and session security (prototype):** TLS, Argon2id-backed account registration/login, connection-bound sessions, authorization by authenticated account name, session expiry, and in-memory per-account login throttling.
8. **Evaluation and reporting:** repeat trials across 1 KB, 10 KB, 100 KB, and 1 MB payloads; report latency, throughput, delivery and rejection outcomes, and variability. Keep raw CSV, graph source, and evidence reproducible.

The supplied six-phase proposal places basic messaging first, then encryption, key establishment, attacks, account/session security, and a dashboard. The research blueprint also lists environment setup as Phase 1 and gives Java 21 as the finalized stack. Phases 1–5 now have prototype implementations; the dashboard and experimental evaluation/reporting remain. We use a Java socket relay and local account store rather than MongoDB/Socket.IO because the finalized implementation is Java-based.

## Controlled attack lab

The localhost-only proxy can observe ciphertext metadata, tamper with one encrypted message, replay one message, or alter one signed key announcement. Since TLS is enabled, the proxy uses the local server certificate to terminate and re-establish TLS; this models a trusted/compromised TLS endpoint for teaching application-layer controls. Follow [docs/attack-lab.md](docs/attack-lab.md). The proxy only accepts loopback targets and binds to loopback itself.

## Research work to complete

- Review 5–10 primary research/standards sources on E2EE, authenticated key exchange, replay protection, and key rotation; map each source to a feature and avoid novelty claims until this review is complete.
- Specify a threat model, trust assumptions, key verification model, replay-state persistence, and limits (two users, text messages, local controlled environment).
- Define baseline/proposed comparisons and experiment protocol before collecting results. Expected outcomes are hypotheses, not reported findings.
- Record implementation versions, JVM warm-up, hardware/OS, payload sizes, trial counts, and summary statistics so measurements can be reproduced.
- Keep secrets and private keys out of source control and audit logs; never log message plaintext or authentication tokens.

JUnit 5 is configured for later security and behavior tests. Phase 5 is an educational prototype: use a trusted terminal for passwords, protect local certificate/private identity files, and do not expose this relay to a network. The account file is not encrypted at rest; TLS client authentication and robust multi-instance persistent session/rate-limit storage are not implemented.
