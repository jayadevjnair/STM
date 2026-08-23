use stm_signature::{
    generate_signing_key,
    public_key_bytes,
    sign_merkle_root,
    verifying_key_from_bytes,
    verify_merkle_root,
};

#[test]
fn sign_and_verify_merkle_root() {
    // Generate a signing key.
    let signing_key = generate_signing_key();

    // Example 32-byte Merkle root.
    let merkle_root = [42u8; 32];

    // Sign it.
    let signature = sign_merkle_root(&signing_key, &merkle_root);

    // Extract and restore the public key.
    let public_key = public_key_bytes(&signing_key);
    let verifying_key =
        verifying_key_from_bytes(&public_key).unwrap();

    // Verification must succeed.
    let result = verify_merkle_root(
        &verifying_key,
        &merkle_root,
        &signature,
    );

    assert!(result.is_ok());
}

#[test]
fn modified_merkle_root_fails_verification() {
    let signing_key = generate_signing_key();

    let original_root = [42u8; 32];
    let signature =
        sign_merkle_root(&signing_key, &original_root);

    let public_key = public_key_bytes(&signing_key);
    let verifying_key =
        verifying_key_from_bytes(&public_key).unwrap();

    // Attacker changes the Merkle root.
    let modified_root = [99u8; 32];

    let result = verify_merkle_root(
        &verifying_key,
        &modified_root,
        &signature,
    );

    assert!(result.is_err());
}