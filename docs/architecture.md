# SecureConnect architecture notes

## Trust boundaries

| Component | Holds plaintext? | Holds end-to-end keys? | Responsibility |
|---|---:|---:|---|
| Alice/Bob client | Yes, locally | Yes, locally | Identity/key operations, encrypt, authenticate, decrypt, display |
| Relay service (current prototype) | No | No | Route AES-GCM envelopes between localhost clients; usernames are connection labels, not authenticated identities |
| Relay service (target design) | No | No | Authenticate a connection, authorize delivery, route/store ciphertext and delivery metadata |
| Persistence | No | No | Store ciphertext, nonce/tag or serialized AEAD envelope, sender/recipient IDs, message/session IDs, timestamps and delivery state |
| Attack harness | Test fixtures only | Test keys only | Mutate, observe, and replay controlled local traffic for demonstrations |

The current prototype uses client-side AES-256-GCM with a key derived from ephemeral X25519 agreement. Each ephemeral public key and session identifier is signed by a long-term Ed25519 identity key. Clients verify the signature against a manually pinned peer Ed25519 key before deriving a session key with HKDF-SHA-256. The relay binds to localhost and forwards signed key announcements and opaque encrypted envelopes; it does not hold the private identity, ephemeral, or session keys. It has no TLS, persistence, or account authentication, and usernames are connection labels only. Public identity keys must be verified out of band; trusting a key supplied by the relay would allow key substitution. Private identity key files are stored unencrypted for this local prototype. Do not expose it to a network or use sensitive messages.

## Message path

1. Client opens a local TCP connection and registers a username for the duration of that connection.
2. Sender encrypts locally with AES-256-GCM using a random 96-bit nonce and authenticates the sender/recipient routing context as associated data. The envelope contains a version, nonce, ciphertext, and tag.
3. Sender transmits the encoded envelope; relay forwards it to the connected recipient without decrypting it.
4. Recipient checks the envelope and GCM authentication tag locally, then displays plaintext only after successful authentication.
5. Ed25519 identity signatures authenticate ephemeral X25519 public-key announcements. Clients verify the peer's pinned signing key, derive a shared secret with X25519, then derive a 256-bit session key with HKDF-SHA-256 using both signed session IDs and the sorted participant names as context.
6. Target relay authenticates and authorizes the sender, applies rate and replay controls, and stores/forwards the opaque envelope.

Replay protection requires authenticated freshness state and durable or otherwise well-defined duplicate tracking. A freely chosen message ID by itself is not sufficient. The signed handshake currently has no durable replay cache or expiry enforcement. Key rotation must specify how both endpoints synchronize key versions and how delayed messages are handled.

## Scope and limits

Initial scope is two clients, one relay, text payloads, local controlled attack simulations, and reproducible performance measurements. This is an educational design, not a complete production messaging protocol or a substitute for a formal analysis/security audit.
