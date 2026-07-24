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

Nodes survive restarts. This is the minimum requirement before any
network-level features make sense.

- [ ] Save identity keypair on first run, reload on subsequent starts
- [ ] Save and reload peer table on shutdown/startup
- [ ] Persist ratchet state after every encrypt/decrypt
- [ ] Persist signed pre-key and OPK pool
- [ ] Detect corrupted storage and force re-keying rather than
      silently proceeding

---

## Milestone 2: Full X3DH Session Establishment

Replace the simplified DH handshake with the proper X3DH protocol
so sessions have full authentication and offline initiation.

- [ ] Wire `x3dh_initiate` / `x3dh_respond` into the session flow
- [ ] Serialize and send `InitialMessage` over the wire
- [ ] Verify SPK signature before accepting a session
- [ ] Publish pre-key bundles (identity + SPK + OPKs) to relay nodes
- [ ] Fetch pre-key bundles from relays for offline recipients
- [ ] Consume and replenish one-time pre-keys after use
- [ ] Rotate signed pre-keys on a configurable schedule

---

## Milestone 3: Mixnet Routing (Messages Through Sphinx)

Wire the Sphinx infrastructure into the actual send path. This is
where metadata resistance begins.

- [ ] When 3+ relays known, `send_text_message` constructs a Sphinx
      packet instead of sending DirectMessage
- [ ] Route selection uses the existing `select_route` (random 3-5 hops)
- [ ] Sphinx packets enqueued in EpochFlusher with first-hop address
- [ ] Epoch flusher transmits real + cover packets each epoch
- [ ] Relay nodes forward Sphinx packets using address registry
- [ ] Direct TCP is fallback when fewer than 3 relays available
- [ ] End-to-end test: 5 nodes, message through 3 relay hops, delivered

---

## Milestone 4: Poisson Mix Delay

Without mixing delay, a global passive adversary can correlate
packet entry and exit timing at each relay. Poisson delay is the
standard defence.

- [ ] Each relay holds each packet for a random delay drawn from
      a Poisson distribution (configurable lambda parameter)
- [ ] Delay is per-packet, not per-batch (packets from the same
      epoch exit at different times)
- [ ] Cover traffic (loop packets) also experiences the delay so
      real and cover packets have identical timing profiles
- [ ] Delay parameter encoded in the Sphinx routing block (the
      `delay` field already exists, currently unused)
- [ ] Configurable maximum delay to bound latency

---

## Milestone 5: Peer Discovery & Epoch Directory

Real peer discovery so nodes find each other without manual
configuration.

- [ ] **Epoch directory**: each node publishes a signed descriptor
      containing its public key, listen address, and capabilities.
      Descriptors are valid for one epoch and refreshed each epoch.
- [ ] **Directory distribution**: descriptors propagated via gossip
      protocol over the mix overlay, or via a DHT shared among nodes.
- [ ] **Bootstrap from directory**: a new node fetches the directory
      from a bootstrap peer and learns about all active nodes.
- [ ] **Peer table auto-population**: the address registry and
      available_relays list are populated from the directory, not
      just from direct connections.
- [ ] **Descriptor signing**: descriptors signed with the node's
      Ed25519 identity key. Peers verify signatures before trusting.

---

## Milestone 6: SURBs (Single Use Reply Blocks)

Allow anonymous replies without revealing the sender's network
location.

- [ ] Sender constructs a SURB: a pre-built Sphinx header that
      routes a reply back through chosen relays to the sender.
- [ ] SURB included in the message payload (encrypted, so only
      the recipient can use it).
- [ ] Recipient uses the SURB to send a reply without knowing
      the sender's address or route.
- [ ] Each SURB is single-use (replay protection via tag).
- [ ] SURB key material enables the sender to decrypt the reply.

---

## Milestone 7: Sybil Resistance & Admission Control

Prevent attackers from flooding the network with malicious nodes
to deanonymize users.

- [ ] **New node rate limiting**: freshly joined nodes have a
      limited frame injection rate until they accumulate reputation.
- [ ] **Proof-of-work or proof-of-stake admission**: new nodes
      must present PoW/PoS to be accepted into the directory
      (similar to Nym mixnet staking model).
- [ ] **General rate limiting**: all nodes are rate-limited per
      epoch to prevent flooding. Rate tied to epoch directory
      registration.
- [ ] **Relay reputation tracking**: nodes track relay reliability
      (packet delivery success rate, uptime). Routes prefer
      higher-reputation relays.
- [ ] **Eclipse attack resistance**: route selection algorithm
      should avoid choosing too many relays from the same
      network/ASN.

---

## Milestone 8: Multi-Peer & Group Features

- [ ] Peer addressing by ID or alias (send to specific peer)
- [ ] Contact list management (add, remove, name peers)
- [ ] Group messaging (sender-keys or pairwise fanout)
- [ ] Message delivery receipts (via SURBs)
- [ ] Message fragmentation for payloads exceeding frame limit

---

## Milestone 9: Hardening & Audit

- [ ] Remove all `.expect()` / `.unwrap()` in non-test code
- [ ] Zeroize audit: every secret properly cleared on drop
- [ ] Connection retry with exponential backoff
- [ ] Known-answer tests against Signal test vectors
- [ ] Graceful shutdown with full state persistence
- [ ] Sphinx payload encryption upgraded from XOR-based to
      proper SPRP (Lioness wide-block cipher)
- [ ] Formal security review / audit
- [ ] Fuzz testing of wire protocol parser
- [ ] Memory safety audit (no unsafe, verify via cargo-deny)

---

## Milestone 10: User Experience

- [ ] TUI chat interface (ratatui or similar)
- [ ] File transfer over mixnet
- [ ] Mobile platform support (iOS/Android via Rust FFI)
- [ ] Desktop GUI (tauri or similar)
- [ ] Onboarding UX (QR code key exchange, contact sharing)

---

## Design Principles

These are captured in detail in `.specify/memory/constitution.md`
and should be updated via `/speckit.constitution` as new security
requirements are formalised.

Key principles:

1. **Security over convenience.** Every trade-off favours security.
2. **No custom crypto.** Audited libraries only.
3. **Metadata resistance is not optional.** It is an architectural
   requirement, not an afterthought.
4. **Forward secrecy is mandatory.** Every message key is ephemeral.
5. **No central point of failure or trust.**
6. **Secret material is zeroized.** Keys never persist in memory
   longer than needed.
7. **Simplicity.** The simplest correct solution is preferred.

---

## References

- [Signal Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Sphinx: A Compact and Provably Secure Mix Format](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf)
- [Loopix: A Low-Latency Anonymous Communication System](https://arxiv.org/abs/1703.00536)
- [Nym Mixnet Whitepaper](https://nymtech.net/nym-whitepaper.pdf)
- [Katzenpost Sphinx Spec](https://katzenpost.network/docs/specs/sphinx/)
