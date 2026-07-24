<!--
  === Sync Impact Report ===
  Version change: 1.0.0 → 1.1.0
  Bump rationale: MINOR — new security guidance added from design notes.

  Modified principles:
    - V. Privacy by Design: added overlay-ID-only requirement,
      Poisson mixing delay requirement with deterministic seeding,
      cover traffic delay parity requirement.

  Added sections:
    - Security Requirements > Network Admission & Rate Limiting
      (new node rate limiting, per-epoch rate limits, eclipse
      attack resistance in route selection)

  Removed sections: (none)

  Follow-up TODOs: (none)
-->
# Caint Constitution

## Core Principles

### I. Security First

All design and implementation decisions MUST prioritize
confidentiality, integrity, forward secrecy, and metadata
resistance over convenience, performance, or feature velocity.

- No feature, optimization, or refactoring SHALL be merged if it
  weakens the security posture of the system.
- When a trade-off exists between usability and security, security
  MUST win unless an explicit, documented exception is ratified
  through the Governance amendment process.
- Every public API surface MUST be evaluated for its attack surface
  before acceptance.

### II. Cryptographic Correctness

All cryptographic operations MUST use well-audited, peer-reviewed
algorithms and libraries. Rolling custom cryptographic primitives
is prohibited.

- Key exchange MUST use X25519 Diffie-Hellman via `x25519-dalek`.
- Identity signing MUST use Ed25519 via `ed25519-dalek`.
- Symmetric encryption MUST use ChaCha20-Poly1305 (AEAD) via
  `chacha20poly1305`.
- Key derivation MUST use HKDF-SHA256 with domain-separation
  strings unique to each derivation context.
- All random values MUST be sourced from a CSPRNG (`OsRng`).
- Protocol implementations (Double Ratchet, X3DH, Sphinx) MUST
  follow their respective specification documents. Deviations
  MUST be documented with security rationale and flagged for
  independent review.
- No cryptographic parameter (key size, nonce length, MAC tag
  length) SHALL be reduced below the algorithm's recommended
  minimum.

### III. Modular Architecture

The codebase MUST be organized as independent, composable modules
with clear boundaries and minimal coupling.

- Each module (`keys`, `messaging`, `network`, `storage`,
  `transport`, `utils`) MUST have a single, well-defined
  responsibility.
- Cross-module dependencies MUST flow in one direction: higher-level
  modules depend on lower-level modules, never the reverse.
- Public module APIs MUST be defined in `mod.rs` via explicit
  re-exports. Internal implementation details MUST NOT leak through
  public interfaces.
- New modules MUST NOT be introduced without a documented purpose.
  Empty placeholder modules are acceptable only during initial
  scaffolding and MUST be tracked as TODOs.

### IV. Test-Driven Development

Every behavioral change MUST be accompanied by tests. Tests MUST
be written before or concurrently with the implementation they
verify.

- Unit tests MUST cover all public functions and methods.
- Cryptographic operations MUST include known-answer tests (KATs)
  using published test vectors where available.
- Protocol implementations (Double Ratchet, X3DH) MUST include
  round-trip integration tests verifying correct encrypt/decrypt
  and key agreement flows.
- The project MUST NOT merge code that reduces overall test
  coverage.
- `cargo test` MUST pass with zero failures before any commit
  is considered complete.

### V. Privacy by Design

The system MUST minimize metadata exposure at every layer of
the stack. Privacy properties are architectural requirements,
not afterthoughts.

- Message payloads MUST be fixed-size (padded to constant length)
  to resist traffic analysis.
- Onion-routed packets (Sphinx) MUST ensure that no single relay
  can determine both sender and recipient.
- The system MUST NOT log, store, or transmit plaintext message
  content, recipient identifiers, or timing correlations outside
  of the sender and recipient endpoints.
- All persistent storage of user data MUST be encrypted at rest.
- Network transport MUST NOT expose user IP addresses to message
  recipients or intermediary relays beyond the first hop.
- All node identifiers in directories, announcements, and routing
  MUST be overlay IDs (public key fingerprints). Raw IP addresses
  MUST NOT appear in any protocol-level data structure. IP
  resolution MUST be confined to the connection layer only.
- Relay nodes MUST apply per-packet mixing delay drawn from a
  Poisson distribution before forwarding. The delay RNG MUST be
  seeded deterministically from the frame's per-hop nonce to
  prevent timing leaks from RNG state interaction. Cover traffic
  MUST experience the same delay distribution as real traffic.
- All nodes MUST exhibit identical observable behaviour regardless
  of platform or device type. Cover traffic rate, connection
  count, epoch timing, and packet sizes MUST NOT vary between
  mobile and desktop. Any device-specific divergence is a
  fingerprinting vector.

### VI. Memory Safety & Secret Management

Sensitive cryptographic material MUST be handled with explicit
lifetime controls and MUST be erased from memory as soon as it
is no longer needed.

- All secret keys, session keys, and intermediate key material
  MUST implement zeroization on drop (via the `zeroize` crate
  or equivalent).
- Ephemeral secrets MUST be consumed (moved) on use to prevent
  accidental reuse. The type system MUST enforce this where
  possible.
- The project MUST NOT use `unsafe` Rust unless the unsafe block
  is justified in a comment, bounded to the minimum scope, and
  reviewed for soundness.
- Secret material MUST NOT appear in log output, debug formats,
  error messages, or stack traces.

### VII. Simplicity

The simplest correct solution MUST be preferred. Complexity MUST
be justified.

- YAGNI: features, abstractions, and indirections MUST NOT be
  introduced until a concrete, immediate need is demonstrated.
- Each abstraction layer MUST reduce complexity for its consumers;
  abstractions that merely reorganize without simplifying are
  prohibited.
- Dependencies MUST be added only when they provide significant
  value over a simple in-project implementation. Each dependency
  MUST be evaluated for maintenance status, security posture,
  and transitive dependency footprint.
- Code MUST be written for readability. Clever optimizations
  MUST include explanatory comments justifying the trade-off.

### VIII. Political Commitment

This project exists to serve the right to private communication
free from state and corporate surveillance. This commitment is
non-negotiable and supersedes commercial, institutional, or
governmental interests.

- Design decisions MUST NOT accommodate lawful interception,
  backdoors, key escrow, or any mechanism that would allow a
  third party to access communications.
- The project MUST NOT accept funding, partnership, or
  contribution that requires compromising the privacy of users.
- Contributions that weaken privacy to serve convenience,
  compliance, or commercial viability MUST be rejected.

## Security Requirements

### Cryptographic Standards

- All symmetric keys MUST be at least 256 bits.
- All AEAD nonces MUST be unique per key; nonce reuse is a
  critical defect.
- Key derivation MUST use distinct domain-separation strings
  (info parameters) for each derived key purpose.
- Forward secrecy MUST be maintained: compromise of long-term
  keys MUST NOT enable decryption of past session traffic.

### Key Management

- Long-term identity keys (Ed25519) MUST be stored encrypted
  at rest.
- Ephemeral keys MUST be generated per-session and MUST NOT
  persist beyond their immediate use.
- Pre-key bundles for X3DH MUST be rotated on a defined
  schedule (to be specified when the X3DH module is
  implemented).
- Ratchet state MUST be persisted only in encrypted storage.

### Network Admission & Rate Limiting

- New nodes MUST have restricted frame injection rates until they
  accumulate reputation or present proof-of-work/stake. The
  specific mechanism (PoW, PoS, or reputation threshold) is a
  design decision, but the principle that new nodes are not
  immediately trusted at full capacity is non-negotiable.
- All nodes MUST be rate-limited per epoch to prevent flooding.
  The rate limit MUST be tied to the node's epoch directory
  registration.
- Route selection MUST resist eclipse attacks: the algorithm
  MUST avoid concentrating too many hops from the same network
  or autonomous system.

### Dependency Security

- All cryptographic dependencies MUST be pure-Rust
  implementations with no C bindings (to maintain memory
  safety guarantees).
- Dependencies MUST be pinned to exact versions in
  `Cargo.lock`.
- Dependency updates MUST be reviewed for changelog entries
  affecting security before adoption.

## Development Workflow

### Branching and Commits

- All feature work MUST occur on feature branches, not on
  `main` directly.
- Commits MUST be atomic: each commit MUST compile and pass
  `cargo test`.
- Commit messages MUST follow conventional commits format
  (e.g., `feat:`, `fix:`, `refactor:`, `docs:`, `test:`).

### Quality Gates

- `cargo build` MUST complete with zero errors and zero
  warnings (warnings are treated as errors via `#[deny(warnings)]`
  or equivalent CI configuration once CI is established).
- `cargo test` MUST pass with zero failures.
- `cargo clippy` MUST report zero warnings before a branch
  is considered merge-ready.
- `cargo fmt --check` MUST pass (consistent formatting
  enforced).

### Code Review

- All changes to modules under `src/keys/` and `src/messaging/`
  (cryptographic core) MUST be reviewed with particular
  attention to correctness of protocol implementations.
- Security-sensitive changes MUST include a brief threat
  analysis in the PR description.

### Documentation

- Public API functions MUST have rustdoc comments describing
  purpose, parameters, return values, and panics/errors.
- Protocol deviations from reference specifications MUST be
  documented in-code with rationale.

## Governance

This constitution is the governing authority for all design,
implementation, and process decisions in the Caint project.

- **Supremacy**: This constitution supersedes all other guidance,
  conventions, or informal practices. Conflicts MUST be resolved
  in favor of the constitution.
- **Amendment procedure**: Amendments MUST be proposed as changes
  to this file, reviewed, and ratified before taking effect.
  Each amendment MUST include a rationale and a migration plan
  if it affects existing code.
- **Versioning policy**: The constitution version follows semantic
  versioning. MAJOR bumps for principle removals or incompatible
  redefinitions; MINOR bumps for new principles or materially
  expanded guidance; PATCH bumps for clarifications and wording
  fixes.
- **Compliance review**: Every code change MUST be evaluated for
  constitution compliance. Violations MUST be resolved before
  merge. Justified exceptions MUST be documented in a Complexity
  Tracking table referencing the specific principle.

**Version**: 1.1.0 | **Ratified**: 2026-07-23 | **Last Amended**: 2026-07-24
