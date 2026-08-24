use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use tempfile::{tempdir, NamedTempFile};

use stm_chunk::{chunk_file, verify_and_reassemble, ChunkConfig};
use stm_manifest::StorageMode;
use stm_signature::generate_signing_key;
use stm_storage::{ChunkStore, LocalChunkStore};
use stm_transfer::TransferState;

fn hash_file(path: &std::path::Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    hex::encode(hasher.finalize())
}

#[test]
fn e2e_stm_v2_signed_simulation() {
    let workspace = tempdir().unwrap();
    let test_file_path = workspace.path().join("test_file.bin");

    // 1. Create a 10 MB test file
    let file_size = 10 * 1024 * 1024;
    let mut test_file = File::create(&test_file_path).unwrap();
    for i in 0..(file_size / 1024) {
        let chunk = [(i % 256) as u8; 1024];
        test_file.write_all(&chunk).unwrap();
    }
    test_file.flush().unwrap();

    let original_hash = hash_file(&test_file_path);

    // 2. Chunk the file into 4 MiB chunks
    let config = ChunkConfig::default(); // 4 MiB
    let (mut manifest, chunks) = chunk_file(
        &test_file_path,
        &config,
        "application/octet-stream",
        StorageMode::Remote,
    )
    .unwrap();

    // 3. Sign Manifest
    let signing_key = generate_signing_key();
    manifest.sign(&signing_key.to_bytes()).unwrap();

    let manifest_id_before = manifest.manifest_id.clone();

    // Changing transfer_id should not affect manifest_id
    manifest.transfer_id = Some("new-uuid".to_string());
    assert_eq!(manifest.manifest_id, manifest_id_before);
    assert!(manifest.verify_signature().is_ok());

    // 4. Store chunks in LocalChunkStore
    let store_dir = workspace.path().join("chunk_store");
    let store = LocalChunkStore::new(&store_dir).unwrap();

    for (hash, data) in &chunks {
        store.put_chunk(hash, data).unwrap();
    }

    // 5. Simulate interrupted transfer at 50%
    let mut transfer_state = TransferState::from_manifest(&manifest);
    let total = transfer_state.total_chunks;
    let half = total / 2;

    for i in 0..half {
        transfer_state.mark_verified(i);
    }

    let state_path = workspace.path().join("transfer.json");
    transfer_state.save(&state_path).unwrap();

    // 6. Reload TransferState and identify missing chunks (simulation purposes)
    let loaded_state = TransferState::load(&state_path).unwrap();
    assert_eq!(loaded_state.file_id, manifest.transfer_id.clone().unwrap());

    // 7. Verify and reassemble (the pipeline internally retrieves missing chunks from store)
    let output_path = workspace.path().join("reconstructed.bin");

    // In a real scenario, we'd retrieve chunks from network, but here we just pass the store.
    // The pipeline will fetch all chunks from the store and verify them.
    verify_and_reassemble(&manifest, &store, &output_path).unwrap();

    // 8. Compare SHA-256
    let reconstructed_hash = hash_file(&output_path);

    // 9. Result: byte-for-byte identical
    assert_eq!(original_hash, reconstructed_hash);
}
