mod crypto;
mod keys;
mod messaging;
mod storage;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    println!("=== Caint bootstrap demo ===");

    // 1. Initialize keystore with a passphrase
    let passphrase = "super-secret-passphrase";
    let mut ks = keys::key_store::KeyStore::open("keystore.db", passphrase)?;
    let identity = ks.get_or_create_identity()?;
    println!("Loaded identity public key: {:x?}", identity.public);

    // 2. Build a frame
    let payload = b"Hello, secure world!";
    let frame = messaging::frame::Frame::new(payload.to_vec());
    println!("Built frame of size {}", frame.data.len());

    // 3. Encrypt the frame using our crypto layer
    let sym_key = keys::kdf::derive_key_from_passphrase(passphrase)?;
    let ciphertext = crypto::aead::encrypt_message(&sym_key, &frame.data)?;
    let plaintext = crypto::aead::decrypt_message(&sym_key, &ciphertext)?;
    assert_eq!(plaintext, frame.data);

    // 4. Store it encrypted in sled
    let mut db = storage::encrypted_db::EncryptedDb::open("storage.db", &sym_key)?;
    db.put(b"last_frame", &plaintext)?;
    println!("Stored frame securely in encrypted DB.");

    // 5. (later) send frame over Tor transport
    // transport::arti_transport::send_frame(&frame).await?;

    Ok(())
}
