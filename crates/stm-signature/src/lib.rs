use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use stm_core::{Hash, StmError};

pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Generate a new Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Sign an STM Merkle root.
pub fn sign_merkle_root(signing_key: &SigningKey, merkle_root: &Hash) -> [u8; SIGNATURE_SIZE] {
    let signature: Signature = signing_key.sign(merkle_root);
    signature.to_bytes()
}

/// Verify an STM Merkle root signature.
pub fn verify_merkle_root(
    verifying_key: &VerifyingKey,
    merkle_root: &Hash,
    signature_bytes: &[u8; SIGNATURE_SIZE],
) -> Result<(), StmError> {
    let signature = Signature::from_bytes(signature_bytes);

    verifying_key
        .verify(merkle_root, &signature)
        .map_err(|_| StmError::InvalidSignature)
}

/// Get the public key bytes.
pub fn public_key_bytes(signing_key: &SigningKey) -> [u8; PUBLIC_KEY_SIZE] {
    signing_key.verifying_key().to_bytes()
}

/// Restore a verifying key from raw bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Result<VerifyingKey, StmError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| StmError::InvalidPublicKey)
}
