# SecureConnect architecture notes

## Trust boundaries

| Component | Holds plaintext? | Holds end-to-end keys? | Responsibility |
|---|---:|---:|---|
| Alice/Bob client | Yes, locally | Yes, locally | Identity/key operations, encrypt, authenticate, decrypt, display |
| Relay service (current prototype) | No | No | Route AES-GCM envelopes between localhost clients; usernames are connection labels, not authenticated identities |
| Relay service (target design) | No | No | Authenticate a connection, authorize delivery, route/store ciphertext and delivery metadata |
| Persistence | No | No | Store ciphertext, nonce/tag or serialized AEAD envelope, sender/recipient IDs, message/session IDs, timestamps and delivery state |
| Attack harness | Test fixtures only | Test keys only | Mutate, observe, and replay controlled local traffic for demonstrations |

The earlier baseline sent plaintext and has been replaced by client-side AES-256-GCM. The current relay binds to localhost, forwards opaque encrypted envelopes, and does not have the key. It has no TLS, persistence, or account authentication, and usernames are connection labels only. Do not expose it to a network or use sensitive messages. The AES key is manually generated and copied into both clients for demonstration; this does not authenticate key distribution, and either key holder can forge messages. TLS will protect a connection to the relay in a later phase; end-to-end encryption protects message contents from the relay and network observers. These are separate layers. Account authentication does not prove that a recipient's public key is genuine; clients need a trusted verification mechanism for signed identity/key material.

## Message path

1. Client opens a local TCP connection and registers a username for the duration of that connection.
2. Sender encrypts locally with AES-256-GCM using a random 96-bit nonce and authenticates the sender/recipient routing context as associated data. The envelope contains a version, nonce, ciphertext, and tag.
3. Sender transmits the encoded envelope; relay forwards it to the connected recipient without decrypting it.
4. Recipient checks the envelope and GCM authentication tag locally, then displays plaintext only after successful authentication.
5. **Target key establishment:** clients authenticate key material using X25519, Ed25519 signatures, and HKDF-SHA-256 key derivation, replacing manual shared-key setup.
6. Target relay authenticates and authorizes the sender, applies rate and replay controls, and stores/forwards the opaque envelope.

Replay protection requires authenticated freshness state and durable or otherwise well-defined duplicate tracking. A freely chosen message ID by itself is not sufficient. Key rotation must specify how both endpoints synchronize key versions and how delayed messages are handled.

## Scope and limits

Initial scope is two clients, one relay, text payloads, local controlled attack simulations, and reproducible performance measurements. This is an educational design, not a complete production messaging protocol or a substitute for a formal analysis/security audit.
