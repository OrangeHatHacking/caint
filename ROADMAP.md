# Caint Roadmap

This document tracks the path from working E2EE prototype to production
decentralized mixnet messenger. Items are ordered by dependency and
priority. Each milestone builds on the previous.

## Milestone 0: Foundation (DONE)

What exists today.

- [x] Double Ratchet with per-message forward secrecy
- [x] X3DH key agreement (library, not yet in app layer)
- [x] Fixed-size 4096-byte AEAD-encrypted frames
- [x] Sphinx packet construction and processing (3-5 hops)
- [x] Per-hop MAC verification, group element blinding, filler generation
- [x] Replay detection with TTL-based cache expiration
- [x] Loop cover traffic (valid Sphinx packets, dummy marker after final decryption)
- [x] Epoch flusher with cover padding and shuffle
- [x] Encrypted-at-rest storage (identity, ratchets, messages)
- [x] TCP relay listener with wire protocol
- [x] Manual peer bootstrap and session establishment
- [x] Interactive bidirectional messaging
- [x] 106 passing tests, zero clippy warnings

---

## Milestone 1: Persistent Identity & Sessions

Nodes survive restarts. Minimum requirement before network-level
features make sense.

- [ ] Save identity keypair on first run, reload on subsequent starts
- [ ] Save and reload peer table on shutdown/startup
- [ ] Persist ratchet state after every encrypt/decrypt
- [ ] Persist signed pre-key and OPK pool
- [ ] Detect corrupted storage and force re-keying rather than
      silently proceeding

---

## Milestone 2: Full X3DH Session Establishment

Replace the simplified DH handshake with the proper X3DH protocol
for full authentication and offline initiation.

- [ ] Wire `x3dh_initiate` / `x3dh_respond` into the session flow
- [ ] Serialize and send `InitialMessage` over the wire
- [ ] Verify SPK signature before accepting a session
- [ ] Publish pre-key bundles (identity + SPK + OPKs) to relay nodes
- [ ] Fetch pre-key bundles from relays for offline recipients
- [ ] Consume and replenish one-time pre-keys after use
- [ ] Rotate signed pre-keys on a configurable schedule
- [ ] Node-to-node transport keys rotate per epoch or per connection

---

## Milestone 3: Mixnet Routing (Messages Through Sphinx)

Wire Sphinx into the send path. This is where metadata resistance
begins.

- [ ] When 3+ relays known, construct Sphinx packet instead of
      DirectMessage
- [ ] Route selection: random 3-5 hops via `select_route`
- [ ] Sphinx packets enqueued in EpochFlusher with first-hop address
- [ ] Epoch flusher transmits real + cover packets each epoch
- [ ] Relay nodes forward Sphinx packets using address registry
- [ ] All addresses in the system are **overlay IDs** (public key
      fingerprints), never raw IPs. IP resolution happens only at
      the connection layer via the address registry.
- [ ] Direct TCP is fallback when fewer than 3 relays available
- [ ] End-to-end test: 5 nodes, message through 3 relay hops

---

## Milestone 4: Poisson Mix Delay

Without mixing delay, a global passive adversary can correlate
packet entry and exit timing at each relay.

- [ ] Each relay holds each packet for a random delay drawn from
      a Poisson distribution (configurable lambda parameter)
- [ ] Delay is per-packet, not per-batch (packets from the same
      epoch exit at different times)
- [ ] **Delay RNG seeded by the frame's per_hop_nonce** to avoid
      timing leaks from RNG state interaction (deterministic delay
      derivation)
- [ ] Cover traffic also experiences the delay so real and cover
      packets have identical timing profiles
- [ ] Delay parameter encoded in the Sphinx routing block (the
      `delay` field already exists, currently unused)
- [ ] Configurable maximum delay to bound latency
- [ ] Epoch window configurable (5-30 seconds; lower = better UX,
      higher = better privacy; bandwidth trade-off)

---

## Milestone 5: Peer Discovery & Epoch Directory

Real peer discovery. No more manual `--peer` configuration beyond
initial bootstrap.

- [ ] **Epoch directory**: each node publishes a signed descriptor
      containing its overlay ID, capabilities, and optionally its
      `bandwidth_capacity`. Descriptors valid for one epoch.
- [ ] **Overlay IDs only**: directories MUST NOT contain raw IP
      addresses. Routing resolution is separate from identity.
- [ ] **Directory distribution**: descriptors propagated via gossip
      protocol or DHT over the mix overlay.
- [ ] **Bootstrap from directory**: new node fetches directory from
      a bootstrap peer and learns about all active nodes.
- [ ] **Peer table auto-population**: address registry and
      available_relays populated from directory, not just direct
      connections.
- [ ] **Descriptor signing**: signed with Ed25519 identity key.
      Peers verify signatures before trusting.
- [ ] **Reputation-based routing weight**: route selection prefers
      nodes with higher delivery success and uptime. Do NOT publish
      exact bandwidth capacity (fingerprinting risk). If capacity
      tiers are ever needed, use coarse categories only.

---

## Milestone 6: NAT Traversal & Connectivity

Nodes behind NAT must be able to participate without inbound port
forwarding.

- [ ] **QUIC transport** as the primary protocol (preferred over
      raw TLS/TCP). QUIC handles WiFi-to-cellular transitions
      natively via connection migration.
- [ ] Persistent **outbound-only** connections to a rotating set
      of overlay peers (mesh-like topology)
- [ ] Multiplexed streams over a single connection to avoid
      per-message connection overhead
- [ ] No inbound listener required for clients (relay nodes
      still need to accept connections)
- [ ] **Mobile-specific parameters**: reduced peer connections
      (2-3 vs 5-10 for desktop), lower cover traffic rate when
      on battery, with the privacy/battery trade-off transparent
      to the user
- [ ] **Push notification via trusted relay**: lightweight "you
      have mail" signal (no content) to wake backgrounded mobile
      apps for message retrieval
- [ ] Nodes advertise connection list via overlay (which peers
      they can reach), not IP addresses

---

## Milestone 7: SURBs (Single Use Reply Blocks)

Anonymous replies without revealing the sender's network location.

- [ ] Sender constructs a SURB: pre-built Sphinx header routing
      a reply back through chosen relays to the sender
- [ ] SURB included in message payload (encrypted; only recipient
      can use it)
- [ ] Recipient uses SURB to reply without knowing sender's
      address or route
- [ ] Each SURB is single-use (replay protection via tag)
- [ ] SURB key material enables sender to decrypt the reply
- [ ] **Mix node keys in a SURB are only valid for the epoch in
      which the SURB was created** (prevents stale-SURB attacks)
- [ ] **ACKs sent as normal frames through mix overlay using
      SURBs** -- requester's location never disclosed

---

## Milestone 8: Epoch Redundancy & Reliability

Compensate for nodes going offline mid-route and enable async
message delivery.

- [ ] Route each frame along **multiple disjoint paths** (k-of-n
      replication) so delivery succeeds if some relays drop
- [ ] Forward error correction as alternative or supplement to
      full path replication
- [ ] Last-hop nodes buffer frames for a bounded time window with
      **short TTL** (e.g., 24 hours)
- [ ] **Random last-hop selection**: sender picks a different last
      relay each time to prevent fixed-mailbox centralisation
- [ ] **SURB-based retrieval**: recipient pre-distributes SURBs to
      multiple relays. When a message arrives, the relay uses the
      SURB to forward it through the mixnet to the recipient. The
      relay never learns who the recipient is -- it holds only an
      opaque blob and a SURB header.

---

## Milestone 9: Sybil Resistance & Admission Control

Prevent attackers from flooding the network with malicious nodes.

- [ ] **New node rate limiting**: limited frame injection until
      reputation accumulated or PoW/PoS presented
- [ ] **Proof-of-work or proof-of-stake admission** (Nym model)
- [ ] **General rate limiting**: all nodes rate-limited per epoch,
      rate tied to directory registration
- [ ] **Relay reputation tracking**: delivery success rate, uptime;
      routes prefer higher-reputation relays
- [ ] **Eclipse attack resistance**: route selection avoids too
      many relays from the same network/ASN

---

## Milestone 10: Multi-Peer & Group Features

- [ ] Peer addressing by ID or alias
- [ ] Contact list management (add, remove, name)
- [ ] Group messaging (sender-keys or pairwise fanout)
- [ ] Message delivery receipts (via SURBs)
- [ ] Message fragmentation / splitting for payloads exceeding
      the 4096-byte frame limit

---

## Milestone 11: Hardening & Audit

- [ ] Remove all `.expect()` / `.unwrap()` in non-test code
- [ ] Zeroize audit: every secret properly cleared on drop
- [ ] Connection retry with exponential backoff
- [ ] Known-answer tests against Signal test vectors
- [ ] Graceful shutdown with full state persistence
- [ ] Sphinx payload encryption upgraded from XOR-based to
      proper SPRP (Lioness wide-block cipher)
- [ ] Evaluate HPKE for key encapsulation on top of Sphinx + AEAD
- [ ] Formal security review / audit
- [ ] Fuzz testing of wire protocol parser
- [ ] Memory safety audit (no unsafe, verify via cargo-deny)

---

## Milestone 12: User Experience

- [ ] TUI chat interface (ratatui or similar)
- [ ] File transfer over mixnet
- [ ] Mobile platform support (iOS/Android via Rust FFI)
- [ ] Desktop GUI (tauri or similar)
- [ ] Onboarding UX (QR code key exchange, contact sharing)

---

## Design Principles

1. **Security over convenience.** Every trade-off favours security.
2. **No custom crypto.** Audited libraries only.
3. **Metadata resistance is not optional.** Architectural requirement.
4. **Forward secrecy is mandatory.** Every message key is ephemeral.
5. **No central point of failure or trust.**
6. **Overlay identity only.** Raw IPs never appear in directories,
   announcements, or routing. Resolution is a separate layer.
7. **Secret material is zeroized.** Keys never persist in memory
   longer than needed.
8. **Simplicity.** The simplest correct solution is preferred.

---

## References

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Sphinx: A Compact and Provably Secure Mix Format](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf)
- [Loopix: A Low-Latency Anonymous Communication System](https://arxiv.org/abs/1703.00536)
- [Nym Mixnet Whitepaper](https://nymtech.net/nym-whitepaper.pdf)
- [Katzenpost Sphinx Spec](https://katzenpost.network/docs/specs/sphinx/)
