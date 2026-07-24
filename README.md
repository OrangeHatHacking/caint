# Caint

*From the Irish word for "talk" or "speech."*

Fully decentralized end-to-end encrypted messenger with Sphinx mixnet routing for metadata resistance. Written in Rust with no custom cryptography.

The goal is Signal-level encryption with stronger metadata protection: no central server, no phone number, no way for any single party (including relay operators) to determine who is talking to whom.

## Why This Exists

Privacy is an inherent right that is being stolen by surveillance capitalism.

Caint exists because the infrastructure of communication should not be owned, surveilled, or controlled by states or corporations. This project is built on the principles of mutual aid, decentralisation, and the belief that people have an unconditional right to speak privately.

This is a political project. It is anarchist in the truest sense. A commitment to a world built on liberty, equality, and voluntary cooperation rather than coercion. A world without borders used as weapons, without empires extracting wealth from the periphery, without hierarchies that exist to dominate rather than to serve. This project believes in solidarity across every division that power has constructed such as race, gender, sexuality, nationality, and in the dignity of every person to live free from surveillance and control.

It stands against every form of domination: the state, capital, patriarchy, racism, transphobia, homophobia, imperialism, and the apparatus of surveillance that sustains them all. The technology serves the politics and the politics serves the people.

If you use this, contribute back. If you build on it, share it. To take you must also give. That is the deal and the protocols of this messenger have been designed as such to implement these principles as best as possible.

Níl aon saoirse gan saoirse gach duine

## Current State

Caint is a working E2EE messenger. Nodes discover each other, establish encrypted sessions automatically, and exchange messages interactively over TCP. All messages are encrypted with ChaCha20-Poly1305 using per-message keys derived from the Double Ratchet protocol. Forward secrecy is active from the first message.

**What works:**

- End-to-end encryption with per-message forward secrecy (Double Ratchet)
- Automatic session establishment when peers connect (manual bootstrap via `--peer`)
- Interactive bidirectional messaging over TCP
- Encrypted-at-rest storage (identity, sessions, message history)
- Sphinx packet construction and processing (built + tested, not yet in the send path)
- Loop cover traffic generation (valid Sphinx packets indistinguishable from real until final decryption)

**What doesn't work yet:**

- Messages travel directly (TCP), not through the mixnet -- no metadata resistance yet
- No peer discovery -- nodes must be told about each other via `--peer` flag at startup
- Session establishment uses simplified DH instead of full X3DH
- Identity is regenerated on every restart (not persisted)
- No multi-peer addressing (sends to first peer only)

## Threat Model

**Protects against:**

- Passive network observers reading message content (E2E encryption)
- Compromise of a single message key revealing other messages (forward secrecy via ratcheting)
- Compromised relay nodes reading message content (relays only see opaque Sphinx packets; they cannot decrypt the payload, only peel their routing layer)
- Traffic analysis via message size (all frames are fixed at 4096 bytes; all Sphinx packets are fixed at 4429 bytes)
- Traffic analysis via timing and volume (constant-rate transmission with cover traffic -- once mixnet routing is wired in)
- Sender-receiver linkability by any single relay (each relay knows only the previous and next hop, not the full path)

**Does not yet protect against (planned):**

- Global passive adversary correlating traffic timing across all links (requires Poisson mixing delay at relays)
- Sybil attacks flooding the network with malicious relays (requires reputation, proof-of-work, or stake-based admission)
- Long-term intersection attacks (requires sufficient cover traffic volume and user base)

**Does not protect against:**

- Endpoint compromise (if your device is owned, your keys are compromised)
- Coercion / rubber-hose cryptanalysis

## End Goal

A production-grade decentralized messenger where:

1. **Every message travels through a Sphinx mixnet.** The sender constructs a Sphinx packet with a randomly selected 3-5 hop route through relay nodes. Each relay peels one encryption layer, learns only the previous and next hop, and forwards. The recipient decrypts the final layer to recover the message.

2. **Poisson mixing at relays defeats timing analysis.** Each relay holds packets for a random delay drawn from a Poisson distribution before forwarding, breaking the correlation between incoming and outgoing packet timing. This is the key defence against a global passive adversary.

3. **Constant-rate cover traffic makes real messages indistinguishable.** Every node transmits a fixed number of packets per epoch. Gaps are filled with loop cover packets -- valid Sphinx packets routed through the network back to the sender. An observer sees constant traffic regardless of real activity.

4. **SURBs enable anonymous replies.** Single Use Reply Blocks allow a recipient to respond to a message without knowing the sender's network location. The sender includes a pre-constructed Sphinx header that routes the reply back through the mixnet.

5. **Offline messaging via X3DH pre-key bundles.** A sender establishes a session with an offline recipient by fetching their pre-key bundle from a relay and performing X3DH key agreement. The encrypted message is stored and forwarded when the recipient comes online.

6. **Epoch directory with signed node presence.** Nodes publish their presence (public key, address, capabilities) in an epoch directory signed by the node's private key. Directories are distributed via gossip protocol or DHT over the mix overlay.

7. **Sybil resistance.** New nodes have limited frame injection rates until they accumulate reputation or present proof-of-work/stake, similar to the Nym mixnet model. All nodes are rate-limited to prevent flooding.

8. **No central server.** No registration, no key server, no message queue. Every node is a peer that relays for others.

## Architecture

```
src/
├── keys/
│   ├── identity.rs      Ed25519 + X25519 identity keypair
│   ├── prekey.rs         Signed pre-keys, one-time pre-keys, bundles
│   ├── x3dh.rs           X3DH key agreement (initiate + respond)
│   └── ratchet.rs        Double Ratchet (symmetric + DH ratchet)
├── messaging/
│   └── frame.rs          Fixed-size 4096-byte AEAD-encrypted frames
├── transport/
│   ├── sphinx.rs         Sphinx packet create/process, replay cache
│   ├── routing.rs        Route selection, per-hop routing blocks
│   ├── blinding.rs       Group element re-randomization
│   ├── filler.rs         Sphinx header filler generation
│   ├── epoch.rs          Constant-rate batch transmission + cover traffic
│   ├── relay.rs          TCP relay listener + packet forwarding
│   ├── connection.rs     TCP connection pool
│   ├── prekey_relay.rs   Relay-side pre-key bundle storage
│   └── wire.rs           Wire protocol (message framing + types)
├── storage/
│   └── encrypted.rs      Encrypted file I/O (identity, ratchets, messages)
├── network/
│   ├── peers.rs          Peer table + message routing
│   └── session.rs        Session management
├── app.rs                Application runtime
├── config.rs             Configuration
└── main.rs               CLI entry point
```

## Cryptographic Primitives

| Purpose | Algorithm | Crate |
|---------|-----------|-------|
| Identity signing | Ed25519 | `ed25519-dalek` |
| Key exchange | X25519 | `x25519-dalek` |
| Message encryption | ChaCha20-Poly1305 (AEAD) | `chacha20poly1305` |
| Key derivation (root ratchet) | HKDF-SHA256 | `hkdf` + `sha2` |
| Key derivation (chain ratchet) | HMAC-SHA256 | `hmac` + `sha2` |
| Sphinx header encryption | ChaCha20 | `chacha20` |
| Sphinx payload encryption | ChaCha20 (XOR-based) | `chacha20` |
| Random number generation | OsRng (CSPRNG) | `rand` |

No custom cryptographic primitives. All crypto from audited RustCrypto and Dalek crates.

## Quick Start

```bash
# Build
cargo build --release

# Terminal 1
./target/release/caint run --listen 127.0.0.1:9001

# Terminal 2
./target/release/caint run --listen 127.0.0.1:9002 --peer 127.0.0.1:9001

# Type in either terminal. Messages appear in the other as:
# [peer_id...]: your message
```

### Commands

```
caint run [options]     Start the node (relay + messenger)
caint init              Generate identity and print public keys

Options:
  --listen <addr>       Listen address (default: 0.0.0.0:9000)
  --data <path>         Storage directory (default: ./caint_data)
  --peer <addr>         Bootstrap peer (repeatable)
  --epoch <ms>          Epoch interval in ms (default: 1000)

In-app:
  /peers                List known peers
  /quit                 Shutdown

Environment:
  RUST_LOG=caint=debug  Verbose logging
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full development plan, ordered by
dependency and priority. The short version:

1. **Persistent identity & sessions** -- survive restarts
2. **Full X3DH** -- proper session authentication
3. **Mixnet routing** -- messages through Sphinx, not direct TCP
4. **Poisson mix delay** -- defeat timing correlation at relays
5. **Peer discovery & epoch directory** -- real discovery, not manual bootstrap
6. **SURBs** -- anonymous replies
7. **Sybil resistance** -- PoW/PoS admission, rate limiting, reputation
8. **Group messaging & UX**
9. **Hardening & audit**

## Tests

```bash
cargo test               # Full suite (106 tests)
cargo test keys::        # Key agreement + ratchet
cargo test messaging::   # Frame encryption
cargo test transport::   # Sphinx + routing + epochs
cargo test storage::     # Encrypted persistence
cargo test network::     # Peer management
```

## License

[AGPL-3.0](https://www.gnu.org/licenses/agpl-3.0.html)

If you modify caint and deploy it as a network service, you must release your source code under the same license. This keeps the protocol open and prevents proprietary forks with weakened security.
