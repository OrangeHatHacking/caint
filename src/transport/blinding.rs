//! Group element re-randomization for Sphinx packets.
//!
//! Each hop re-randomizes the group element (alpha) using a blinding factor
//! derived from the per-hop shared secret, so successive hops cannot link packets.

use x25519_dalek::{PublicKey, StaticSecret};

/// Blind the alpha (group element) for the next hop.
///
/// alpha_next = blinding_factor * alpha (scalar multiplication on Curve25519)
pub fn blind_alpha(alpha: &PublicKey, blinding_factor: &[u8; 32]) -> PublicKey {
    let blind_secret = StaticSecret::from(*blinding_factor);
    let blinded = blind_secret.diffie_hellman(alpha);
    PublicKey::from(*blinded.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_blinding_produces_different_key() {
        let mut alpha_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut alpha_bytes);
        // Clamp to valid X25519 point
        let secret = StaticSecret::from(alpha_bytes);
        let alpha = PublicKey::from(&secret);

        let mut bf = [0u8; 32];
        OsRng.fill_bytes(&mut bf);

        let blinded = blind_alpha(&alpha, &bf);
        assert_ne!(alpha.to_bytes(), blinded.to_bytes());
    }

    #[test]
    fn test_blinding_deterministic() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let alpha = PublicKey::from(&secret);

        let bf = [42u8; 32];

        let blinded1 = blind_alpha(&alpha, &bf);
        let blinded2 = blind_alpha(&alpha, &bf);
        assert_eq!(blinded1.to_bytes(), blinded2.to_bytes());
    }
}
