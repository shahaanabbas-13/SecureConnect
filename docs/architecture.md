# SecureConnect architecture notes

## Trust boundaries

| Component | Holds plaintext? | Holds end-to-end keys? | Responsibility |
|---|---:|---:|---|
| Alice/Bob client | Yes, locally | Yes, locally | Identity/key operations, encrypt, authenticate, decrypt, display |
| Relay service | No | No | Authenticate a connection, authorize delivery, route/store ciphertext and delivery metadata |
| Persistence | No | No | Store ciphertext, nonce/tag or serialized AEAD envelope, sender/recipient IDs, message/session IDs, timestamps and delivery state |
| Attack harness | Test fixtures only | Test keys only | Mutate, observe, and replay controlled local traffic for demonstrations |

TLS protects a connection to the relay. End-to-end encryption protects message contents from the relay and network observers. These are separate layers. Account authentication does not prove that a recipient's public key is genuine; clients need a trusted verification mechanism for signed identity/key material.

## Message path

1. Clients establish and authenticate key material (planned: X25519 key agreement with Ed25519 signatures and HKDF-SHA-256 key derivation).
2. Sender encrypts locally with AES-256-GCM using a fresh, unique nonce for the key and binds relevant routing/session fields as associated data.
3. Sender transmits an envelope containing version, conversation/session ID, message ID or sequence, sender/recipient routing IDs, key version, nonce, and ciphertext/tag.
4. Relay authenticates and authorizes the sender, applies rate and duplicate controls, and stores/forwards the opaque envelope.
5. Recipient validates context and freshness, verifies/decrypts locally, and only then displays plaintext.

Replay protection requires authenticated freshness state and durable or otherwise well-defined duplicate tracking. A freely chosen message ID by itself is not sufficient. Key rotation must specify how both endpoints synchronize key versions and how delayed messages are handled.

## Scope and limits

Initial scope is two clients, one relay, text payloads, local controlled attack simulations, and reproducible performance measurements. This is an educational design, not a complete production messaging protocol or a substitute for a formal analysis/security audit.
