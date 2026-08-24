pub mod remote;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use stm_core::StmError;
use stm_manifest::StmManifest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    pub file_id: String,
    pub total_chunks: u64,
    /// Rule: Downloaded + Hash Verified = Completed
    /// Only verified chunks are saved in this list.
    pub verified_chunks: Vec<u64>,
}

impl TransferState {
    pub fn new(file_id: String, total_chunks: u64) -> Self {
        Self {
            file_id,
            total_chunks,
            verified_chunks: Vec::new(),
        }
    }

    pub fn from_manifest(manifest: &StmManifest) -> Self {
        Self::new(
            manifest
                .transfer_id
                .clone()
                .unwrap_or_else(|| "unknown-transfer".to_string()),
            manifest.total_chunks,
        )
    }

    pub fn mark_verified(&mut self, chunk_index: u64) {
        if !self.verified_chunks.contains(&chunk_index) {
            self.verified_chunks.push(chunk_index);
            self.verified_chunks.sort_unstable();
        }
    }

    pub fn get_missing_chunks(&self) -> Vec<u64> {
        let mut missing = Vec::new();
        for i in 0..self.total_chunks {
            if !self.verified_chunks.contains(&i) {
                missing.push(i);
            }
        }
        missing
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), StmError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        let mut file = File::create(path).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        file.write_all(json.as_bytes()).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, StmError> {
        let mut file = File::open(path).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        let mut json = String::new();
        file.read_to_string(&mut json).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        let state = serde_json::from_str(&json).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })?;
        Ok(state)
    }
}
