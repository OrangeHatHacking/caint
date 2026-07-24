# Design Notes

Raw design notes and open questions. Canonical implementation plan
is in [ROADMAP.md](ROADMAP.md). These notes capture intent and ideas
that haven't been formalised yet.

## Protocol Design

### Frame Format

```
| Header (Sphinx onion) | Body (AEAD payload) | MAC |
```

- **Header**: per-hop encrypted. Each hop sees only `next_hop_id` (overlay ID, not IP), `per_hop_nonce`, and a routing MAC. Previous hops stripped away.
- **Body**: AEAD-encrypted payload for end recipient. Sphinx "forward" indicator if intermediary. Random-padded to fixed 4096 bytes before encryption.
- **MAC**: Poly1305 over header + body for tamper detection.

### Ephemeral Routing & Epochs

- Epoch window: 5-30 seconds (lower = better UX, higher = better privacy; bandwidth trade-off).
- Each node maintains `incoming_buffer` (collects during epoch) and `outgoing_buffers` (per next-hop, assembled and shuffled at epoch boundary).
- **Poisson delay**: each forwarded frame gets a delay drawn from a Poisson distribution. Delay RNG seeded by the frame's `per_hop_nonce` to avoid timing leaks from RNG state interaction.

### SURBs

- Pre-computed Sphinx headers containing a mixnet route back to the SURB creator.
- Sender generates one or more SURBs and includes them in their message.
- Recipient uses the SURB as the Sphinx header for their reply or ACK.
- Single-use (replay protection via tag). Mix node keys in the SURB are only valid for the epoch in which the SURB was created.
- **ACKs are sent as normal frames through the mix overlay using SURBs**, so the requester's location is never disclosed.

### Cover Traffic

- Each node maintains a minimum `cover_rate` (dummies per second) tied to bandwidth capacity.
- Cover frames are cryptographically identical to real frames (encrypted, MACed, routed through the mixnet).
- **Decision**: do NOT publish bandwidth capacity in the epoch directory. Capacity values fingerprint nodes. Routing weight is derived from reputation (delivery success, uptime) instead.

### NAT Traversal & Connectivity

- Clients maintain persistent **outbound** TLS connections to a rotating set of peers (mesh-like). Multiplexed streams over TLS or QUIC avoid requiring inbound port acceptance.
- Works behind NAT: no listener required. Outbound-only connections to overlay peers.
- Each node advertises an **overlay ID** and connection list -- never raw IPs. Published only inside signed directories or via current peers.
- **Decision**: QUIC is the primary transport. Connection migration handles network transitions natively. All nodes MUST behave identically regardless of platform -- differing cover traffic rates or connection counts between mobile and desktop would be a fingerprinting vector. Uniform behaviour is non-negotiable.

## Sender -> Receiver Flow

1. **Identity**: each user has an identity key pair and an overlay routing address (cryptographic handle, not IP). Peer list from bootstrap nodes or DHT.
2. **Encrypt**: plaintext encrypted with X3DH / Double Ratchet. Ciphertext packed into fixed-size 4096-byte frame (split or pad as needed).
3. **Route**: choose N hops (N random from 3-5). Compute Sphinx header layers.
4. **Submit**: inject frame to local mix queue -> outbound peers. If behind NAT, use persistent outbound connections.
5. **Mix**: nodes collect incoming frames during epoch. At epoch boundary, shuffle outgoing batch, add/remove dummies to quota, sample per-packet Poisson delay for randomised output times.
6. **Deliver**: last hop strips final layer and delivers ciphertext to recipient's handler. Recipient fetches when online. SURBs for replies.
7. **ACK**: acknowledgements travel as normal frames via SURBs.

## Epoch Redundancy & Reliability

- Route each frame along **multiple disjoint paths** to compensate for nodes going offline (k-of-n replication).
- Forward error correction and/or parallel frames as alternatives.
- **Decision**: last-hop buffering uses SURB-based retrieval. Recipient pre-distributes SURBs to multiple relays. When a message arrives, the relay uses the SURB to forward it through the mixnet -- the relay never learns who the recipient is. Sender picks a random last-hop each time. Short TTL (e.g., 24 hours) on buffered messages.

## Rekeying & Forward Secrecy

- All E2E payloads use short-lived ephemeral keys and the ratchet protocol.
- Node-to-node transport keys rotate per epoch or per connection.

## Node Directory & Trust

- Nodes publish presence in an **epoch directory** signed with the node's Ed25519 key.
- Directories distributed via **gossip protocol or DHT over the mix overlay**.
- Overlay IDs only -- no IP addresses in directories.

## Sybil Resistance (Ideas)

All under consideration, no final design:

- **Proof-of-work** for new node registration (raises cost of Sybil)
- **Staking incentives** (Nym mixnet model)
- **Per-epoch rate limits** on newer nodes until reputation accumulated (still vulnerable to well-resourced adversaries)
- **General rate limiting** of all nodes
- ~~Social trust graphs as deterrent~~ **(rejected)**: fundamentally at odds with a privacy-focused mixnet. If you can build a trust graph you've already leaked relationship metadata. Works at bootstrap level only, not as a general Sybil defence.
- ~~Personhood validation for relay nodes (rejected: requires de-anonymisation)~~
- I2P's Kademlia DHT (reference only, not privacy-focused enough for this use case)

## Crypto Primitives (Reference)

- **Key exchange**: X25519 ephemeral DH
- **Enveloping**: HPKE (not yet implemented; evaluate whether needed on top of Sphinx + AEAD)
- **AEAD payload**: ChaCha20-Poly1305 (preferred over AES-GCM; hardware acceleration not assumed)
- **Sphinx construction**: PRF, MAC, per-hop padding, filler
- **Constant-time operations**: audited Rust crypto crates (RustCrypto, Dalek)
