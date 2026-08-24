use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use stm_chunk::{chunk_file, verify_and_reassemble, ChunkConfig};
use stm_manifest::StorageMode;
use stm_signature::generate_signing_key;
use stm_storage::{ChunkStore, LocalChunkStore};

fn setup_env() -> (
    tempfile::TempDir,
    stm_manifest::StmManifest,
    LocalChunkStore,
    std::path::PathBuf,
) {
    let workspace = tempdir().unwrap();
    let test_file_path = workspace.path().join("test_file.bin");

    let file_size = 1 * 1024 * 1024;
    let mut test_file = File::create(&test_file_path).unwrap();
    for i in 0..(file_size / 1024) {
        let chunk = [(i % 256) as u8; 1024];
        test_file.write_all(&chunk).unwrap();
    }
    test_file.flush().unwrap();

    let config = ChunkConfig::default();
    let (mut manifest, chunks) = chunk_file(
        &test_file_path,
        &config,
        "application/octet-stream",
        StorageMode::Remote,
    )
    .unwrap();

    let signing_key = generate_signing_key();
    manifest.sign(&signing_key.to_bytes()).unwrap();

    let store_dir = workspace.path().join("chunk_store");
    let store = LocalChunkStore::new(&store_dir).unwrap();

    for (hash, data) in &chunks {
        store.put_chunk(hash, data).unwrap();
    }

    let output_path = workspace.path().join("reconstructed.bin");

    (workspace, manifest, store, output_path)
}

#[test]
fn test_tamper_manifest_filename() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.filename = "hacked.txt".to_string();
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_tamper_manifest_mime_type() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.mime_type = "text/plain".to_string();
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_tamper_chunk_order() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    if manifest.chunks.len() > 1 {
        manifest.chunks.swap(0, 1);
        assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
    }
}

#[test]
fn test_tamper_chunk_hash() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.chunks[0].hash[0] ^= 0xFF;
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_tamper_merkle_root() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.merkle_root[0] ^= 0xFF;
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_tamper_signature() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    let mut sig = manifest.signature.unwrap();
    sig = sig.replace("0", "1");
    manifest.signature = Some(sig);
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_missing_chunk_in_store() {
    let (_workspace, manifest, store, output_path) = setup_env();
    store.delete_chunk(&manifest.chunks[0].hash).unwrap();
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_tamper_chunk_in_store() {
    let (workspace, manifest, store, output_path) = setup_env();
    let hash = &manifest.chunks[0].hash;
    store.delete_chunk(hash).unwrap();

    // Bypass put_chunk validation to write corrupted chunk
    let hex_hash = hex::encode(hash);
    let chunk_path = workspace.path().join("chunk_store").join(hex_hash);
    std::fs::write(&chunk_path, b"hacked data bytes!").unwrap();

    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_missing_chunk_indexes() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.chunks.remove(0);
    // Even if signature wasn't checked, this would fail the chunk count check.
    // Let's remove signature so it passes that step and fails the structural check.
    manifest.signature = None;
    manifest.public_key = None;
    manifest.manifest_id = hex::encode(manifest.content_hash());
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_non_contiguous_indexes() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.chunks[0].index = 99;
    manifest.signature = None;
    manifest.public_key = None;
    manifest.manifest_id = hex::encode(manifest.content_hash());
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}

#[test]
fn test_invalid_total_size() {
    let (_workspace, mut manifest, store, output_path) = setup_env();
    manifest.original_size += 1;
    manifest.signature = None;
    manifest.public_key = None;
    manifest.manifest_id = hex::encode(manifest.content_hash());
    assert!(verify_and_reassemble(&manifest, &store, &output_path).is_err());
}
