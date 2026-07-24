//! Group element re-randomization for Sphinx packets.

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use x25519_dalek::PublicKey;

/// Clamp bytes and convert to a curve25519-dalek Scalar (mod L reduction).
fn clamp_and_reduce(bytes: &[u8; 32]) -> Scalar {
    let mut clamped = *bytes;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    Scalar::from_bytes_mod_order(clamped)
}

/// Blind the alpha (group element) for the next hop.
///
/// alpha_next = clamp_reduce(blinding_factor) * alpha
///
/// Uses Scalar * MontgomeryPoint (unclamped scalar after initial clamp+reduce)
/// for consistency with the sender's chain in sphinx.rs.
pub fn blind_alpha(alpha: &PublicKey, blinding_factor: &[u8; 32]) -> PublicKey {
    let bf_scalar = clamp_and_reduce(blinding_factor);
    let alpha_point = MontgomeryPoint(alpha.to_bytes());
    let blinded = bf_scalar * alpha_point;
    PublicKey::from(blinded.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use x25519_dalek::StaticSecret;

    #[test]
    fn test_blinding_produces_different_key() {
        let secret = StaticSecret::random_from_rng(OsRng);
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
