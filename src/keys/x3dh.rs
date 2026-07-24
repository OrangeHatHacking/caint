use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::keys::identity::IdentityKeyPair;
use crate::keys::prekey::{OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::keys::X3DHError;

/// The initial message sent from initiator to responder after X3DH.
#[derive(Debug)]
pub struct InitialMessage {
    /// Initiator's Ed25519 identity public key bytes
    pub identity_key_ed: [u8; 32],
    /// Initiator's X25519 identity public key bytes
    pub identity_key_x: [u8; 32],
    /// Initiator's ephemeral X25519 public key bytes
    pub ephemeral_key: [u8; 32],
    /// Which SPK was used
    pub spk_id: u32,
    /// Which OPK was used (None if exhausted)
    pub opk_id: Option<u32>,
}

/// Domain separator for X3DH HKDF: 32 bytes of 0xFF
const X3DH_F: [u8; 32] = [0xFF; 32];

/// Derive SK from the concatenated DH outputs via HKDF-SHA256.
fn derive_sk(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32], dh4: Option<&[u8; 32]>) -> [u8; 32] {
    // Build IKM: F || DH1 || DH2 || DH3 [|| DH4]
    let mut ikm = Vec::with_capacity(32 * 4 + if dh4.is_some() { 32 } else { 0 });
    ikm.extend_from_slice(&X3DH_F);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(dh4_bytes) = dh4 {
        ikm.extend_from_slice(dh4_bytes);
    }

    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"caint_x3dh", &mut sk)
        .expect("HKDF expand should not fail for 32 bytes");
    sk
}

/// Perform X3DH as the initiator (Alice).
///
/// Generates an ephemeral key, verifies the SPK signature, computes DH1-DH4
/// (DH4 only if OPK present), and derives the shared secret SK.
///
/// Returns (shared_secret, initial_message) or X3DHError.
pub fn x3dh_initiate(
    identity: &IdentityKeyPair,
    peer_bundle: &PreKeyBundle,
) -> Result<([u8; 32], InitialMessage), X3DHError> {
    // Verify SPK signature
    if !peer_bundle.verify_spk_signature() {
        return Err(X3DHError::InvalidSignature);
    }

    // Generate ephemeral X25519 keypair (StaticSecret to allow multiple DH ops)
    let ek_private = StaticSecret::random_from_rng(OsRng);
    let ek_public = X25519PublicKey::from(&ek_private);

    // DH1: IK_A (identity X25519) * SPK_B
    let dh1 = identity.x25519_dh(&peer_bundle.signed_prekey);

    // DH2: EK_A * IK_B (identity X25519)
    let dh2 = *ek_private
        .diffie_hellman(&peer_bundle.identity_x)
        .as_bytes();

    // DH3: EK_A * SPK_B
    let dh3 = *ek_private
        .diffie_hellman(&peer_bundle.signed_prekey)
        .as_bytes();

    // DH4: EK_A * OPK_B (only if OPK present)
    let dh4 = peer_bundle
        .one_time_prekey
        .map(|opk_pub| *ek_private.diffie_hellman(&opk_pub).as_bytes());

    let sk = derive_sk(&dh1, &dh2, &dh3, dh4.as_ref());

    let initial_message = InitialMessage {
        identity_key_ed: identity.ed25519_public_bytes(),
        identity_key_x: identity.x25519_public_bytes(),
        ephemeral_key: ek_public.to_bytes(),
        spk_id: peer_bundle.spk_id,
        opk_id: peer_bundle.opk_id,
    };

    Ok((sk, initial_message))
}

/// Perform X3DH as the responder (Bob).
///
/// Uses stored private keys to compute the same DH operations as the initiator
/// and derive the same shared secret SK.
pub fn x3dh_respond(
    identity: &IdentityKeyPair,
    spk: &SignedPreKey,
    opk: Option<&OneTimePreKey>,
    initial_msg: &InitialMessage,
) -> Result<[u8; 32], X3DHError> {
    let ek_pub = X25519PublicKey::from(initial_msg.ephemeral_key);
    let ik_a_x = X25519PublicKey::from(initial_msg.identity_key_x);

    // DH1: SPK_B * IK_A
    let dh1 = spk.diffie_hellman(&ik_a_x);

    // DH2: IK_B * EK_A
    let dh2 = identity.x25519_dh(&ek_pub);

    // DH3: SPK_B * EK_A
    let dh3 = spk.diffie_hellman(&ek_pub);

    // DH4: OPK_B * EK_A (only if OPK was used)
    let dh4 = opk.map(|opk_key| *opk_key.private_key().diffie_hellman(&ek_pub).as_bytes());

    let sk = derive_sk(&dh1, &dh2, &dh3, dh4.as_ref());

    Ok(sk)
}

/// Compute the Associated Data (AD) for the session.
///
/// AD = IK_A_ed25519_pub || IK_B_ed25519_pub
pub fn compute_ad(initiator_ed25519_pub: &[u8; 32], responder_ed25519_pub: &[u8; 32]) -> [u8; 64] {
    let mut ad = [0u8; 64];
    ad[..32].copy_from_slice(initiator_ed25519_pub);
    ad[32..].copy_from_slice(responder_ed25519_pub);
    ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::prekey::{generate_one_time_prekeys, PreKeyBundle, SignedPreKey};

    #[test]
    fn test_x3dh_full_handshake_with_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opks = generate_one_time_prekeys(1, 5);
        let bob_bundle = PreKeyBundle::build(&bob, &bob_spk, Some(&bob_opks[0]));

        let (alice_sk, initial_msg) = x3dh_initiate(&alice, &bob_bundle).unwrap();
        let bob_sk = x3dh_respond(&bob, &bob_spk, Some(&bob_opks[0]), &initial_msg).unwrap();

        assert_eq!(alice_sk, bob_sk, "Both parties must derive the same SK");
        assert_ne!(alice_sk, [0u8; 32], "SK must not be all zeros");
    }

    #[test]
    fn test_x3dh_handshake_without_opk() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_bundle = PreKeyBundle::build(&bob, &bob_spk, None);

        let (alice_sk, initial_msg) = x3dh_initiate(&alice, &bob_bundle).unwrap();
        assert!(initial_msg.opk_id.is_none());

        let bob_sk = x3dh_respond(&bob, &bob_spk, None, &initial_msg).unwrap();

        assert_eq!(
            alice_sk, bob_sk,
            "Both parties must derive the same SK without OPK"
        );
    }

    #[test]
    fn test_x3dh_fails_with_invalid_signature() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();

        // Sign the SPK with the wrong identity
        let bad_spk = SignedPreKey::generate(&other, 1);
        let mut bad_bundle = PreKeyBundle::build(&bob, &bad_spk, None);
        // The bundle has bob's identity but other's signature
        bad_bundle.spk_signature = bad_spk.signature;

        let result = x3dh_initiate(&alice, &bad_bundle);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), X3DHError::InvalidSignature));
    }

    #[test]
    fn test_x3dh_different_sessions_produce_different_sks() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let bob_spk = SignedPreKey::generate(&bob, 1);
        let bob_opks = generate_one_time_prekeys(1, 2);

        let bundle1 = PreKeyBundle::build(&bob, &bob_spk, Some(&bob_opks[0]));
        let bundle2 = PreKeyBundle::build(&bob, &bob_spk, Some(&bob_opks[1]));

        let (sk1, _) = x3dh_initiate(&alice, &bundle1).unwrap();
        let (sk2, _) = x3dh_initiate(&alice, &bundle2).unwrap();

        // Different OPKs should produce different session keys
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn test_compute_ad() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let ad = compute_ad(&alice.ed25519_public_bytes(), &bob.ed25519_public_bytes());
        assert_eq!(ad.len(), 64);
        assert_eq!(&ad[..32], &alice.ed25519_public_bytes());
        assert_eq!(&ad[32..], &bob.ed25519_public_bytes());
    }
}
