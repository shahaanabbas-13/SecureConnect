# SecureConnect

SecureConnect is an educational Java messaging project for studying end-to-end encryption, authenticated key establishment, replay protection, controlled attack simulations, and their performance costs.

## Current milestone: Phase 6 visual secure chat

The Java 21 prototype establishes an encrypted session between two clients. Ed25519 identity keys sign ephemeral X25519 public keys; clients verify a pinned peer identity, then use HKDF-SHA-256 to derive AES-256-GCM session keys. TLS protects the client-to-relay connection. Accounts use Argon2id password verifiers; authenticated sessions belong to one TLS connection and expire after 30 minutes total or 10 minutes idle. The local relay forwards signed key announcements and encrypted message envelopes but never receives the end-to-end session key or message plaintext. Phase 6 provides a desktop chat UI that visualizes encryption/decryption and a security-event dashboard for attacks and session activity.

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

The supplied six-phase proposal places basic messaging first, then encryption, key establishment, attacks, account/session security, and a dashboard. The research blueprint also lists environment setup as Phase 1 and gives Java 21 as the finalized stack. Phases 1–6 now have prototype implementations, including visual secure chat; experimental evaluation and reporting remain. We use a Java socket relay and local account store rather than MongoDB/Socket.IO because the finalized implementation is Java-based.

## Phase 6: Visual chat and security dashboard

Launch one desktop chat window for each user from separate PowerShell terminals. Build first, then set the TLS truststore settings in each client terminal:

```powershell
mvn package
$env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
$env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
java -jar target/secureconnect-1.0-SNAPSHOT.jar desktop Alice Bob
```

In the second terminal, use the same truststore settings and launch the other side:

```powershell
$env:SECURECONNECT_TLS_TRUSTSTORE = (Resolve-Path .\certs\client-truststore.p12).Path
$env:SECURECONNECT_TLS_TRUSTSTORE_PASSWORD = '<truststore password>'
java -jar target/secureconnect-1.0-SNAPSHOT.jar desktop Bob Alice
```

The desktop app prompts for login or registration. It reads the peer's pinned public key from `SECURECONNECT_TRUSTED_PEER_KEY` or `keys\<peer>.ed25519.public`, displays its SHA-256 fingerprint, and asks you to confirm you checked that fingerprint over a trusted channel. Send a message after both clients show the authenticated end-to-end session. Each message appears as a chat bubble; **Show encrypted payload** reveals the SC1 envelope that crossed the relay, along with sequence and key epoch. On receipt the bubble identifies local GCM-tag/sequence verification and decryption. The side panel shows TLS, identity verification, HKDF session readiness, key epoch, replay state, and live audit activity. The relay sees the encrypted envelope and routing metadata, not the plaintext.

The **Open security monitor** button opens the full audit dashboard. To see a controlled tamper/replay/eavesdrop scenario in the visual client, start the documented `attack-proxy` mode first, then launch both desktop clients through port `5051`, for example `desktop Alice Bob 127.0.0.1 5051`. The visual chat shows accepted plaintext only after verification; rejected tampering/replay and attack activity appear in its live activity feed and the full monitor. The attack proxy still runs as a separate local process, as described in [docs/attack-lab.md](docs/attack-lab.md).

The monitor can also be launched alone in a separate terminal:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar dashboard
```

The dashboard refreshes every two seconds from `data\security-events.tsv`. It summarizes recent authentication/session/rejection events and simulated attack activity, and provides search and severity filters. Up to the latest 5,000 valid events are shown. Set `SECURECONNECT_EVENT_LOG` in every terminal before launching a process if the audit log should use a different shared path.

Audit entries include timestamps, event types, severity, account name where relevant, and a short description. They do not include passwords, message plaintext, cryptographic keys, or ciphertext. The audit log is local and ignored by Git; neither desktop view exposes a network endpoint.

## Experimental evaluation: crypto microbenchmark

Build the project, then run the benchmark from the project folder:

```powershell
mvn package
java -jar target/secureconnect-1.0-SNAPSHOT.jar benchmark
```

The default run measures 100 samples per metric after 100 warm-up iterations for 1 KB, 10 KB, 100 KB, and 1 MB payloads. All metrics are warmed together, then sample order rotates to reduce order effects. You can set the measured iterations, warm-up iterations, and output directory:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar benchmark 200 20 .\experiments\results
```

Each run writes three artifacts under `experiments\results`: a raw CSV with every timed sample, a summary CSV with mean/median/p95/standard deviation and throughput, and a metadata text file with the JVM, operating system, architecture, processor count, memory, payload sizes, and run settings. The repository ignores generated result files so measured data can be reviewed before being committed as research evidence.

Generate latency and throughput PNG charts from a summary CSV without adding a plotting dependency:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar benchmark-chart .\experiments\results\secureconnect-<run-id>-summary.csv
```

The two charts are written beside the summary CSV. Repeat the benchmark command for independent runs; each run receives a unique ID and keeps its raw samples and metadata.

Aggregate independent runs after collecting summaries with matching payloads and iteration settings:

```powershell
$summaries = Get-ChildItem .\experiments\results\secureconnect-*-summary.csv |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
java -jar target/secureconnect-1.0-SNAPSHOT.jar benchmark-aggregate $summaries.FullName
```

The aggregator rejects duplicate run IDs, incomplete/mismatched metric sets, or different sample/warm-up settings. It writes one CSV beside the input summaries with the mean of per-run mean latencies, between-run sample standard deviation, min/max run means, mean per-run medians and p95 values, and average throughput. It does not pool raw samples across JVM runs.

Metrics are `plaintext_copy_baseline`, `protected_encrypt`, `protected_decrypt`, and `protected_round_trip`. The protected path uses the actual HKDF-derived message-key schedule and AES-256-GCM implementation. Timing includes nonce generation and per-operation cipher/key derivation. It excludes sockets, TLS, login, UI, and disk I/O. The baseline is an in-memory byte-array copy whose result is retained, not an unencrypted network transmission. Treat these as local microbenchmark measurements; they do not establish end-to-end network latency or general performance claims. Repeat runs on the same machine and report their variability before drawing conclusions.

### TLS relay end-to-end delivery benchmark

This benchmark logs in two existing local accounts, establishes the same signed X25519/HKDF session used by the clients, then sends encrypted messages through the running TLS relay. Keep both accounts logged out in other terminals. The command prompts for both passwords without echo when run from a terminal. The client truststore environment variables described above must be set in this terminal, and the relay must be running with its server keystore configured.

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar network-benchmark Alice Bob 100
```

The command sends 1 KB, 10 KB, 100 KB, and 1 MB messages, with 10 warm-up messages and 100 measured messages per size. It accepts a different iteration count and optional loopback host/port:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar network-benchmark Alice Bob 200 127.0.0.1 5050
```

Each run writes raw per-message timings, a summary CSV, and metadata under `experiments\results`. Measured latency starts before sender encryption and stops after the receiver authenticates and decrypts the delivered message. It includes TLS socket I/O, loopback TCP, relay routing, and both clients' message cryptography; account login, TLS connection setup, X25519/Ed25519 session establishment, per-message audit append time, and warm-up messages are excluded. The raw CSV separates sender encryption/encoding, sender socket write/flush, wait for delivery, receiver decode/decrypt, total send-to-decrypt, and post-decrypt acknowledgement wait. The relay sends `SENT` only after the audit append, and the benchmark waits for that acknowledgement after stopping the timer to keep audit I/O from overlapping the next sample. The benchmark is restricted to loopback and requires both accounts to be available for its duration.

To aggregate independent network runs, pass the matching summary CSVs. They must use the same payload sizes, sample counts, and warm-up counts. This calculates between-run variability from run means instead of pooling individual observations:

```powershell
$summaries = Get-ChildItem .\experiments\results\secureconnect-network-*-summary.csv |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5
java -jar target/secureconnect-1.0-SNAPSHOT.jar network-benchmark-aggregate $summaries.FullName
```

The aggregator writes a CSV with mean-of-run-means, between-run standard deviation, min/max run means, mean per-run median and p95, throughput, and average timing for each measured phase. It also creates latency and phase charts beside the CSV. Review the selected files before aggregation if the results folder contains runs with different settings or test conditions.

For optional JVM garbage-collection diagnostics, use a colon before the decorators and set an explicit log file. Start the relay and benchmark with separate filenames:

```powershell
java "-Xlog:gc*:file=experiments/results/relay-gc.log:time,uptime,level,tags" -jar target/secureconnect-1.0-SNAPSHOT.jar server
java "-Xlog:gc*:file=experiments/results/benchmark-gc.log:time,uptime,level,tags" -jar target/secureconnect-1.0-SNAPSHOT.jar network-benchmark Alice Bob 100
```

The earlier form `-Xlog:gc*:time,uptime,level,tags` can interpret the decorator text as a filename. Each JVM writes its own log; compare timestamps with the raw sample timings. GC logs can show whether a collection pause coincided with an outlier, but they do not by themselves identify OS or socket delays.

### Message-layer security-control trials

Run repeatable local checks of the message integrity and sequence controls used by the client:

```powershell
java -jar target/secureconnect-1.0-SNAPSHOT.jar security-evaluation
```

The default runs 100 trials each for ciphertext tampering, duplicate replay, out-of-order sequence, and an invalid key version. Set the count and output directory with `security-evaluation 500 .\experiments\results`. Results are written to a CSV with attempts, rejected attempts, and detection percentage. Every trial also verifies that a valid message is accepted before the attack checks. These controlled local trials exercise message-layer code; they do not measure live network attack rates, server capacity, or complete end-to-end session behavior. Replay state is scoped to the client session and resets when a new client process starts.

## Controlled attack lab

The localhost-only proxy can observe ciphertext metadata, tamper with one encrypted message, replay one message, or alter one signed key announcement. Since TLS is enabled, the proxy uses the local server certificate to terminate and re-establish TLS; this models a trusted/compromised TLS endpoint for teaching application-layer controls. Follow [docs/attack-lab.md](docs/attack-lab.md). The proxy only accepts loopback targets and binds to loopback itself.

## Research work to complete

See [docs/evaluation-results.md](docs/evaluation-results.md) for recorded cryptography, security-control, and TLS-relay results, their limits, and the repeat-run protocol. Network summary CSVs can now be aggregated into between-run statistics and phase charts.

- Review 5–10 primary research/standards sources on E2EE, authenticated key exchange, replay protection, and key rotation; map each source to a feature and avoid novelty claims until this review is complete.
- Specify a threat model, trust assumptions, key verification model, replay-state persistence, and limits (two users, text messages, local controlled environment).
- Define baseline/proposed comparisons and experiment protocol before collecting results. Expected outcomes are hypotheses, not reported findings.
- Record implementation versions, JVM warm-up, hardware/OS, payload sizes, trial counts, and summary statistics so measurements can be reproduced.
- Keep secrets and private keys out of source control and audit logs; never log message plaintext or authentication tokens.

JUnit 5 is configured for later security and behavior tests. Phase 5 is an educational prototype: use a trusted terminal for passwords, protect local certificate/private identity files, and do not expose this relay to a network. The account file is not encrypted at rest; TLS client authentication and robust multi-instance persistent session/rate-limit storage are not implemented.
