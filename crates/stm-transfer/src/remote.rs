use reqwest::Client;
use std::sync::Arc;
use stm_core::StmError;
use stm_manifest::StmManifest;
use stm_storage::ChunkStore;
use stm_crypto::hash_bytes;

use crate::TransferState;

pub struct RemoteTransfer {
    server_url: String,
    client: Client,
}

impl RemoteTransfer {
    pub fn new(server_url: String) -> Self {
        Self {
            server_url,
            client: Client::new(),
        }
    }

    pub async fn upload_manifest(&self, manifest: &StmManifest) -> Result<(), StmError> {
        let url = format!("{}/api/v1/manifests", self.server_url);
        let res = self.client.post(&url).json(manifest).send().await.map_err(|e| {
            StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;

        if !res.status().is_success() {
            return Err(StmError::InvalidObject);
        }
        Ok(())
    }

    pub async fn download_manifest(&self, manifest_id: &str) -> Result<StmManifest, StmError> {
        let url = format!("{}/api/v1/manifests/{}", self.server_url, manifest_id);
        let res = self.client.get(&url).send().await.map_err(|e| {
            StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;

        if !res.status().is_success() {
            return Err(StmError::InvalidObject);
        }

        let manifest: StmManifest = res.json().await.map_err(|e| {
            StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;

        // Verify it immediately as per user instructions
        if manifest.signature.is_none() || manifest.public_key.is_none() {
            return Err(StmError::InvalidSignature);
        }
        manifest.verify_signature()?;
        
        // Also verify the requested ID matches what we downloaded
        if manifest.manifest_id != manifest_id {
            return Err(StmError::InvalidObject);
        }

        Ok(manifest)
    }

    pub async fn upload_missing_chunks(
        &self,
        transfer_state: &mut TransferState,
        manifest: &StmManifest,
        chunks_data: &[(stm_core::Hash, Vec<u8>)],
    ) -> Result<(), StmError> {
        let missing_indexes = transfer_state.get_missing_chunks();

        for &idx in &missing_indexes {
            let desc = manifest.chunks.iter().find(|c| c.index == idx).ok_or(StmError::InvalidObject)?;
            
            // Find data in chunks_data
            let chunk_data = &chunks_data.iter().find(|(h, _)| h == &desc.hash).ok_or(StmError::InvalidObject)?.1;
            
            let hex_hash = hex::encode(&desc.hash);
            let chunk_url = format!("{}/api/v1/chunks/{}", self.server_url, hex_hash);

            // 1. HEAD to check if exists
            let head_res = self.client.head(&chunk_url).send().await.map_err(|e| {
                StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })?;

            if head_res.status().is_success() {
                transfer_state.mark_verified(idx);
                continue;
            }

            // 2. POST to upload
            let post_res = self.client.post(&chunk_url).body(chunk_data.clone()).send().await.map_err(|e| {
                StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })?;

            if !post_res.status().is_success() {
                return Err(StmError::InvalidObject); // Upload rejected
            }

            // 3. Mark completed after network confirms stored
            transfer_state.mark_verified(idx);
        }

        Ok(())
    }

    pub async fn download_missing_chunks<S: ChunkStore>(
        &self,
        transfer_state: &mut TransferState,
        manifest: &StmManifest,
        store: &S,
    ) -> Result<(), StmError> {
        let missing_indexes = transfer_state.get_missing_chunks();

        for &idx in &missing_indexes {
            let desc = manifest.chunks.iter().find(|c| c.index == idx).ok_or(StmError::InvalidObject)?;
            
            let hex_hash = hex::encode(&desc.hash);
            let chunk_url = format!("{}/api/v1/chunks/{}", self.server_url, hex_hash);

            // GET chunk
            let res = self.client.get(&chunk_url).send().await.map_err(|e| {
                StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })?;

            if !res.status().is_success() {
                return Err(StmError::InvalidObject);
            }

            let bytes = res.bytes().await.map_err(|e| {
                StmError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })?;

            let data = bytes.to_vec();

            // SHA-256 verify BEFORE atomic write
            let actual_hash = hash_bytes(&data);
            if actual_hash != desc.hash {
                // Malicious server data: reject and abort
                return Err(StmError::InvalidSignature);
            }

            // Atomic ChunkStore write
            store.put_chunk(&desc.hash, &data)?;

            // Mark completed
            transfer_state.mark_verified(idx);
        }

        Ok(())
    }
}
