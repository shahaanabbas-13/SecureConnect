# SecureConnect

SecureConnect is an educational Java messaging project for studying end-to-end encryption, authenticated key establishment, replay protection, controlled attack simulations, and their performance costs.

## Current milestone: Phase 1 — Environment and project foundation

The repository is a Java 21 Maven project. Phase 1 establishes a reproducible local setup and documents the system boundaries before implementing messaging or cryptography.

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

## Planned implementation sequence

1. **Foundation (current):** verify Java/Maven/VS Code, keep the Maven build reproducible, establish project conventions and architecture boundaries.
2. **Secure messaging baseline:** implement a local two-user messaging flow and relay/API boundary using Java. Keep initial dummy messages non-sensitive; introduce persistence only after choosing a Java-compatible store.
3. **Authenticated encryption:** add AES-256-GCM on clients and carry nonce, ciphertext, and tag; reject authentication failures.
4. **Key establishment:** use X25519 and HKDF-SHA-256 for session keys, with Ed25519-authenticated identity/key material. State clearly that this is an educational protocol, not a production replacement for a reviewed messaging protocol.
5. **Replay and key lifecycle:** add authenticated message identifiers/sequence state, duplicate rejection, and controlled session-key rotation.
6. **Controlled attack experiments:** demonstrate ciphertext observation, tampering, replay, impersonation/key substitution, and rate limiting only against the local test system.
7. **Evaluation and reporting:** repeat trials across 1 KB, 10 KB, 100 KB, and 1 MB payloads; report latency, throughput, delivery and rejection outcomes, and variability. Keep raw CSV, graph source, and evidence reproducible.

The attached six-phase proposal places basic messaging first, then encryption, key establishment, attacks, account/session security, and a dashboard. The research blueprint also lists environment setup as Phase 1 and gives Java 21 as the finalized stack. This repository follows the latter numbering for the current setup milestone; the proposal's basic-messaging work is the next implementation milestone. We will adapt MongoDB/Socket.IO from the proposal rather than adopt them automatically, because the finalized implementation is Java-based.

## Research work to complete

- Review 5–10 primary research/standards sources on E2EE, authenticated key exchange, replay protection, and key rotation; map each source to a feature and avoid novelty claims until this review is complete.
- Specify a threat model, trust assumptions, key verification model, replay-state persistence, and limits (two users, text messages, local controlled environment).
- Define baseline/proposed comparisons and experiment protocol before collecting results. Expected outcomes are hypotheses, not reported findings.
- Record implementation versions, JVM warm-up, hardware/OS, payload sizes, trial counts, and summary statistics so measurements can be reproduced.
- Keep secrets and private keys out of source control and audit logs; never log message plaintext or authentication tokens.

## Build and run

After verifying the tools above:

```powershell
mvn package
java -cp target/classes com.secureconnect.Main
```

JUnit 5 is already configured for later security and behavior tests.
