use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use stm_core::{Hash, StmError};
use stm_crypto::hash_bytes;
use tempfile::NamedTempFile;

pub trait ChunkStore {
    fn put_chunk(&self, hash: &Hash, data: &[u8]) -> Result<(), StmError>;
    fn get_chunk(&self, hash: &Hash) -> Result<Vec<u8>, StmError>;
    fn has_chunk(&self, hash: &Hash) -> Result<bool, StmError>;
    fn delete_chunk(&self, hash: &Hash) -> Result<(), StmError>;
}

pub struct LocalChunkStore {
    base_dir: PathBuf,
}

impl LocalChunkStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, StmError> {
        let base_dir = base_dir.as_ref().to_path_buf();
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).map_err(|e| {
                StmError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
        }
        Ok(Self { base_dir })
    }

    fn get_prefixed_chunk_path(&self, hash: &Hash) -> PathBuf {
        let hex_hash = hex::encode(hash);
        let prefix = &hex_hash[0..2];
        self.base_dir.join(prefix).join(&hex_hash)
    }

    fn get_legacy_chunk_path(&self, hash: &Hash) -> PathBuf {
        let hex_hash = hex::encode(hash);
        self.base_dir.join(&hex_hash)
    }

    fn get_chunk_path(&self, hash: &Hash) -> PathBuf {
        let prefixed = self.get_prefixed_chunk_path(hash);
        if prefixed.exists() {
            return prefixed;
        }
        let legacy = self.get_legacy_chunk_path(hash);
        if legacy.exists() {
            return legacy;
        }
        // Default to prefixed for new writes
        prefixed
    }
}

impl ChunkStore for LocalChunkStore {
    fn put_chunk(&self, hash: &Hash, data: &[u8]) -> Result<(), StmError> {
        if self.has_chunk(hash)? {
            return Ok(()); // Deduplication: already exists
        }

        // Verify hash before storing
        let actual_hash = hash_bytes(data);
        if &actual_hash != hash {
            return Err(StmError::InvalidSignature);
        }

        let chunk_path = self.get_chunk_path(hash);
        let parent_dir = chunk_path.parent().unwrap_or(&self.base_dir);
        if !parent_dir.exists() {
            fs::create_dir_all(parent_dir).map_err(|e| {
                StmError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
        }

        // Atomic write
        let mut temp_file = NamedTempFile::new_in(parent_dir).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        temp_file.write_all(data).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        temp_file.flush().map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        temp_file.persist(chunk_path).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        Ok(())
    }

    fn get_chunk(&self, hash: &Hash) -> Result<Vec<u8>, StmError> {
        let chunk_path = self.get_chunk_path(hash);
        if !chunk_path.exists() {
            return Err(StmError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Chunk not found",
            )));
        }

        let mut file = File::open(chunk_path).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        Ok(data)
    }

    fn has_chunk(&self, hash: &Hash) -> Result<bool, StmError> {
        Ok(self.get_chunk_path(hash).exists())
    }

    fn delete_chunk(&self, hash: &Hash) -> Result<(), StmError> {
        let chunk_path = self.get_chunk_path(hash);
        if chunk_path.exists() {
            fs::remove_file(chunk_path).map_err(|e| {
                StmError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;
        }
        Ok(())
    }
}
