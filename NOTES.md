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





# Core Concepts
- End to end ratchet protocol encryption
- sphinx style onion routing
	- Nodes can only decrypt next hop from header, not payload or deeper layers of the header's destinations. Previous hops stripped away
- Batching & mixing
	- Collect frames in epochs then output randomly after delay created by poisson mixing or exponential delays
- Cover/dummy traffic
	- Nodes inject cryptographically identical 'dummy' frames to maintain minimum traffic volume
- Single use reply blocks (SURBs)
	- Offline recipients can receive replies without revealing network locators. Let sender create route to recipient even if recipient is offline
- Node selection
	- Select peers for a route from a signed epcoh directory built via federation of directory signers or distributed consensus, or DHT with rep
	
# Protocol Designs
**Frames**
|Header|Body|MAC|
- Header
	- Sphinx style, encrypted onion routing per hop
		- next_hop_id (overlay ID or public key fingerprint)
		- per_hop_nonce (not once value unique to each hop/destination)
		- routing mac (maybe?)
- Body
	- AEAD encrypted payload for end recipient
	- Sphinx "forward" indicator if intermediary
	- Random padding to bring to full length before encryption
- MAC
	- Cryptographic auth (probably poly1305) over header & body to detect tampering
	
## Cryptographic Primitives
- Key Exchange
	- X25519 for ephemeral Diffie-Helman
- Asymmetric Encryption
	- HPKE for enveloping
- AEAD for Payload
	- ChaCha20-Poly1305 (or maybe AES-GCM on accelerated hardware but preference for chachapoly)
- Sphinx Construction for Onion Headers
	- PRF, MAC, per hop padding, etc.
- Constant-Time Libraries
	- Evercrypt/HACL* bindings or preferably audited crates from Rust specific crypto libraries

## Ephemeral Routing & Epochs
- E.g. 5-30s epochs depending on privacy vs latency (aim lower for sake of usability but be wary of bandwidth usage)
- Nodes Contain:
	- incoming_buffer (collects frames during epoch)
	- outgoing_buffers (per next hop lists assembled & shuffled at epoch boundary)
- Delay
	- Each frame to be forwarded assigned delay from posson distribution
	- Deterministic RNG seeded by frame's per_hop_nonce to avoid RNG interaction timing leaks

## SURBs (Single Use Reply Blocks)
- Pre-computed Sphinx packet headers that contain a mixnet route back to the creator of said SURB
- Senders can generate one or more SURBs and include them i their messages
- Recipient uses SURB to reply or ACK (becomes sphinx header for response)
- Like onion address but single use to prevent replay attacks
- Mix node public keys used to prepare SURB are only valid for a different epoch

## Cover/Dummy Traffic
- Each node maintains minimum 'cover_rate' (x dummies per sec) tied to bandwidth capacity
- Cover frames are indistinguishable from real ones (both are encrypted & MACed)
- Nodes share "bandwidth_capacity" signed into epoch directory so peers can weight routing accordingly (could this have potential for de-anonymisation?)

## Peer Connectivity Model (NAT Traversal)
- Clients maintain persistent outbound TLS connections to a rotating set of peers (like a mesh network) and use multiplexed streams over TLS to avoid requiring inbound accept. They also work behind NAT (QUIC or TLS & HTTPS/2)
- Each node advertises an overlay ID and list of connections to other nodes (only published inside signed directories or via current peers, not IPs)

## Node Directory & Trust
- Nodes publish presence in an epoch directory signed with the node's private key
- Directories are published/exchanged via gossip protocol or using DHT over mix overlay
- New nodes are rate limited in accepted frame injection until reputation accumulated or proof of work/stake is presented
- Network could require minimum proof of work per new node session

**Addendum Notes Misc.**
- Epoch Redundancy
	- Route each frame along multiple disjointed paths to compensate for nodes going offline (k out of n replication)
	- Use forward error correction and/or multiple parallel frames
- Caching
	- Last hop nodes buffer frames for bounded window then SURBs & mailbox retrieval could allow async pickup (mailbox doesn't sit right though, find other way)
- Rekeying & Forward Secrecy
	- All E2E payloads use short lived ephemeral keys & ratchet protocol
- Purely decentralised mixnet built from client nodes
- Every node runs some mix protocol of accepting/forwarding fixed size packets, performing batching & adding delays, and injecting cover traffic

## Sender -> Receiver Protocol
**Discovery & Identity**
Each user has ID key (public key pair) and routing address (cryptographic handle or onion like address); The address is an overlay identifier, not IP. Clients get peer list/epoch directory from bootstrap nodes or DHT

**Message Creation**
Plaintext encrypted with X3DH/double ratchet. Ciphertext is then packed into a fixed size frame, splitting or padding as necessary (4096 bytes)

**Route Computation**
Choose route of N hops where N is random value from range 3-5. Compute sphinx style header layer (each hop can only read next hop encrypted pointer)

**Frame Submission**
Sender submits frame to local mix queue and injects it to one or more peers (outbound only) according to overlay. If behind NAT, maintain persistent outbound TLS/TCP connections to selected peers so no inbound accept is required (is there a cleaner way of doing this? Seems heavy on bandwidth and battery eventually for mobile)

**Node Mixing**
Nodes collect incoming frames during current epoch window. At epoch expiration the outgoing batch of frames is shuffled and forwarded to their next hops. Dummy frames are added/removed according to quota. Delay distribution sampled per-packet for randomised output times

**Delivery**
Last hop strips final layer (without knowing it is the last one) and delivers payload (ciphertext) to recipient's mailbox/handler. Recipient can fetch from local node when online. SURBs for replies without exposing a network location

**Acknowledgement**
ACKs sent back as normal frames through mix overlay using SURBs to avoid disclosing requester of said ACK

# Sybil Attack Mitigations
All random ideas
- Proof of work signups/registrations
- Staking incentives (NYM mixnet as example design)
- Reputation with per epoch limits on newer nodes (still vulnerable to larger adversaries)
- Social trust graphs as a deterrent (might not work in a mixnet of dummy traffic)
- ~~Personhood validation for relay type nodes? De-anonymise temporarily?~~
- I2P implementation of kademlia (not privacy focused)
- General rate limiting of all nodes

