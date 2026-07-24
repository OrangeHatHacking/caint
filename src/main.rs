use caint::keys::identity::IdentityKeyPair;
use caint::keys::prekey::{generate_one_time_prekeys, PreKeyBundle, SignedPreKey};
use caint::keys::ratchet::Ratchet;
use caint::keys::x3dh::{x3dh_initiate, x3dh_respond};

fn main() {
    println!("=== Caint E2EE Messaging System ===\n");

    // 1. Generate identities
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    println!("[OK] Generated identity keys for Alice and Bob");

    // 2. Bob publishes pre-key bundle
    let bob_spk = SignedPreKey::generate(&bob, 1);
    let bob_opks = generate_one_time_prekeys(1, 10);
    let bob_bundle = PreKeyBundle::build(&bob, &bob_spk, Some(&bob_opks[0]));
    println!("[OK] Bob's pre-key bundle created");

    // 3. Alice initiates X3DH
    let (alice_sk, initial_msg) =
        x3dh_initiate(&alice, &bob_bundle).expect("X3DH initiation failed");
    println!("[OK] Alice performed X3DH key agreement");

    // 4. Bob responds to X3DH
    let bob_sk = x3dh_respond(&bob, &bob_spk, Some(&bob_opks[0]), &initial_msg)
        .expect("X3DH response failed");
    assert_eq!(alice_sk, bob_sk, "Shared secrets must match");
    println!("[OK] Bob derived matching shared secret");

    // 5. Initialize Double Ratchet
    let mut alice_ratchet = Ratchet::init_initiator(alice_sk, &bob_spk.public);
    let mut bob_ratchet = Ratchet::init_responder(bob_sk, {
        // In real code, bob would pass his SPK private key
        // For demo, we create a new ratchet with the shared secret
        x25519_dalek::StaticSecret::from(bob_spk.private_key().to_bytes())
    });
    println!("[OK] Double Ratchet initialized for both parties");

    // 6. Exchange a message
    let ad = b"caint_demo";
    let (header, ciphertext) = alice_ratchet.encrypt(b"Hello, Bob!", ad);
    let plaintext = bob_ratchet
        .decrypt(&header, &ciphertext, ad)
        .expect("Decryption failed");
    assert_eq!(plaintext, b"Hello, Bob!");
    println!("[OK] Alice -> Bob: \"Hello, Bob!\" (encrypted & decrypted)");

    // 7. Bob replies
    let (header2, ct2) = bob_ratchet.encrypt(b"Hi Alice!", ad);
    let pt2 = alice_ratchet
        .decrypt(&header2, &ct2, ad)
        .expect("Decryption failed");
    assert_eq!(pt2, b"Hi Alice!");
    println!("[OK] Bob -> Alice: \"Hi Alice!\" (encrypted & decrypted)");

    println!("\n=== All checks passed! ===");
}
