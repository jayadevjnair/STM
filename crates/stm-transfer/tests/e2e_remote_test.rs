use reqwest::Client;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

use stm_core::Hash;
use stm_crypto::hash_bytes;
use stm_manifest::{ChunkDescriptor, StmManifest, StorageMode};
use stm_signature::generate_signing_key;
use stm_storage::{ChunkStore, LocalChunkStore};
use stm_storage_server::{
    config::ServerConfig,
    router::create_router,
    state::AppState,
};
use stm_transfer::{remote::RemoteTransfer, TransferState};

async fn spawn_test_server(base_dir: String) -> (String, Arc<AppState>) {
    let config = ServerConfig {
        base_dir,
        max_chunk_size: 4 * 1024 * 1024,
    };
    let state = Arc::new(AppState::new(config).unwrap());
    
    let app = create_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), state)
}

fn generate_test_chunk(idx: u64, size: usize) -> (Hash, Vec<u8>) {
    let data = vec![(idx % 255) as u8; size];
    let hash = hash_bytes(&data);
    (hash, data)
}

#[tokio::test]
async fn test_a_server_hash_forgery_rejected() {
    let server_dir = TempDir::new().unwrap();
    let (server_url, _) = spawn_test_server(server_dir.path().to_str().unwrap().to_string()).await;

    let client = Client::new();
    let fake_hash = vec![0u8; 32];
    let fake_hash_hex = hex::encode(fake_hash);
    let chunk_url = format!("{}/api/v1/chunks/{}", server_url, fake_hash_hex);

    let res = client.post(&chunk_url).body(vec![1, 2, 3]).send().await.unwrap();
    
    assert_eq!(res.status().as_u16(), 400); // Bad request because computed hash != fake_hash
}

#[tokio::test]
async fn test_b_invalid_manifest_rejected() {
    let server_dir = TempDir::new().unwrap();
    let (server_url, _) = spawn_test_server(server_dir.path().to_str().unwrap().to_string()).await;
    let remote = RemoteTransfer::new(server_url);

    let mut manifest = StmManifest::new(
        "test.txt".to_string(),
        "text/plain".to_string(),
        100,
        1024,
        1,
        vec![],
        [0u8; 32],
        StorageMode::Remote,
        0,
    );
    
    // Unsigned is rejected
    let res = remote.upload_manifest(&manifest).await;
    assert!(res.is_err());

    let private_key = generate_signing_key();
    manifest.sign(&private_key.to_bytes()).unwrap();

    // Tampered manifest ID
    manifest.manifest_id = "a".repeat(64);
    let res = remote.upload_manifest(&manifest).await;
    assert!(res.is_err());
}

#[tokio::test]
async fn test_c_deduplication() {
    let server_dir = TempDir::new().unwrap();
    let (server_url, _) = spawn_test_server(server_dir.path().to_str().unwrap().to_string()).await;
    let remote = RemoteTransfer::new(server_url);

    let mut manifest = StmManifest::new(
        "test.txt".to_string(),
        "text/plain".to_string(),
        100,
        1024,
        1,
        vec![],
        [0u8; 32],
        StorageMode::Remote,
        0,
    );
    let (h1, d1) = generate_test_chunk(1, 1024);
    manifest.chunks.push(ChunkDescriptor { index: 0, hash: h1, size: 1024 });
    let chunks = vec![(h1, d1)];
    
    let mut state = TransferState::from_manifest(&manifest);

    // First upload
    remote.upload_missing_chunks(&mut state, &manifest, &chunks).await.unwrap();
    assert_eq!(state.verified_chunks.len(), 1);

    // Reset state and upload again (should be instant via HEAD)
    let mut state2 = TransferState::from_manifest(&manifest);
    remote.upload_missing_chunks(&mut state2, &manifest, &chunks).await.unwrap();
    assert_eq!(state2.verified_chunks.len(), 1);
}

#[tokio::test]
async fn test_d_interrupted_download() {
    let server_dir = TempDir::new().unwrap();
    let (server_url, _) = spawn_test_server(server_dir.path().to_str().unwrap().to_string()).await;
    let remote = RemoteTransfer::new(server_url);

    let mut manifest = StmManifest::new(
        "test.txt".to_string(),
        "text/plain".to_string(),
        2048,
        1024,
        2,
        vec![],
        [0u8; 32],
        StorageMode::Remote,
        0,
    );
    let (h1, d1) = generate_test_chunk(1, 1024);
    let (h2, d2) = generate_test_chunk(2, 1024);
    manifest.chunks.push(ChunkDescriptor { index: 0, hash: h1, size: 1024 });
    manifest.chunks.push(ChunkDescriptor { index: 1, hash: h2, size: 1024 });
    manifest.total_chunks = 2;
    let chunks = vec![(h1, d1), (h2, d2)];
    
    let private_key = generate_signing_key();
    manifest.sign(&private_key.to_bytes()).unwrap();

    // Upload everything
    remote.upload_manifest(&manifest).await.unwrap();
    let mut state = TransferState::from_manifest(&manifest);
    remote.upload_missing_chunks(&mut state, &manifest, &chunks).await.unwrap();

    // Client B
    let client_dir = TempDir::new().unwrap();
    let store = LocalChunkStore::new(client_dir.path()).unwrap();
    
    let downloaded_manifest = remote.download_manifest(&manifest.manifest_id).await.unwrap();
    let mut dl_state = TransferState::from_manifest(&downloaded_manifest);

    // Simulate partial download (only chunk 0)
    dl_state.mark_verified(0);
    store.put_chunk(&h1, &chunks[0].1).unwrap();

    // Now resume download - it should only download chunk 1
    remote.download_missing_chunks(&mut dl_state, &downloaded_manifest, &store).await.unwrap();

    assert_eq!(dl_state.verified_chunks.len(), 2);
    assert!(store.has_chunk(&h2).unwrap());
}

#[tokio::test]
async fn test_e_malicious_server_data() {
    let server_dir = TempDir::new().unwrap();
    let (server_url, server_state) = spawn_test_server(server_dir.path().to_str().unwrap().to_string()).await;
    let remote = RemoteTransfer::new(server_url);

    let mut manifest = StmManifest::new(
        "test.txt".to_string(),
        "text/plain".to_string(),
        1024,
        1024,
        1,
        vec![],
        [0u8; 32],
        StorageMode::Remote,
        0,
    );
    let (h1, _) = generate_test_chunk(1, 1024);
    manifest.chunks.push(ChunkDescriptor { index: 0, hash: h1, size: 1024 });
    manifest.total_chunks = 1;
    let private_key = generate_signing_key();
    manifest.sign(&private_key.to_bytes()).unwrap();

    // Bypass upload validation and put BAD data in server directly
    let bad_data = vec![99u8; 1024];
    // server thinks it has h1, but we give it bad_data
    // We must bypass LocalChunkStore verification to simulate a malicious server!
    let hex_hash = hex::encode(h1);
    let prefix = &hex_hash[0..2];
    let bad_path = server_dir.path().join("chunks").join(prefix).join(&hex_hash);
    std::fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
    std::fs::write(&bad_path, &bad_data).unwrap();

    // Client B attempts to download
    let client_dir = TempDir::new().unwrap();
    let store = LocalChunkStore::new(client_dir.path()).unwrap();
    let mut dl_state = TransferState::from_manifest(&manifest);

    let res = remote.download_missing_chunks(&mut dl_state, &manifest, &store).await;
    
    // Must error because downloaded chunk hash != requested chunk hash
    assert!(res.is_err());
    assert_eq!(dl_state.verified_chunks.len(), 0);
}
