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
2. Each sender maintains an in-memory sequence starting at 1 for the current session. The message key version is `(sequence - 1) / 10`; HKDF derives the AES key for that epoch from the session root.
3. Sender encrypts locally with AES-256-GCM using a random 96-bit nonce. Sender, recipient, sequence, and key version are authenticated as associated data. The envelope contains a version, nonce, ciphertext, and tag; sequence and key version travel in the relay frame.
4. Sender transmits the encoded envelope; relay forwards it to the connected recipient without decrypting it.
5. Recipient requires the next expected sequence, checks the expected key version, verifies the GCM tag locally, then displays plaintext and advances its sequence only after successful authentication.
6. Ed25519 identity signatures authenticate ephemeral X25519 public-key announcements. Clients verify the peer's pinned signing key, derive a shared secret with X25519, then derive a 256-bit session key with HKDF-SHA-256 using both signed session IDs and the sorted participant names as context.
7. Target relay authenticates and authorizes the sender, applies rate controls, and stores/forwards the opaque envelope. The current clients perform replay rejection at the receiver.

The receiver rejects duplicate and out-of-order sequence numbers, and advances its counter only after successful GCM authentication. This state is in memory and resets with a new session; the relay itself does not deduplicate. Key epochs change every 10 messages in each direction. Since each epoch is derived from the retained session root, this is not a forward-secure ratchet: compromise of that root can derive earlier and later epoch keys. The signed handshake also has no durable replay cache or expiry enforcement. A production design needs a reviewed ratchet or fresh authenticated key exchange, durable replay state where needed, and a defined delayed-message policy.

## Scope and limits

Initial scope is two clients, one relay, text payloads, local controlled attack simulations, and reproducible performance measurements. This is an educational design, not a complete production messaging protocol or a substitute for a formal analysis/security audit.
