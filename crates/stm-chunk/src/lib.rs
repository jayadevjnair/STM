use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use stm_core::{Hash, StmError};
use stm_crypto::build_merkle_root;
use stm_crypto::hash_bytes;
use stm_manifest::{ChunkDescriptor, StmManifest, StorageMode};

pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

pub struct ChunkConfig {
    pub chunk_size: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

/// Compute the exact SHA-256 hash of the raw chunk bytes.
pub fn hash_chunk(chunk_data: &[u8]) -> Hash {
    hash_bytes(chunk_data)
}

/// Verify if a given chunk matches the expected hash.
pub fn verify_chunk(chunk_data: &[u8], expected_hash: &Hash) -> bool {
    &hash_chunk(chunk_data) == expected_hash
}

/// Chunk a file from disk, calculate hashes, and build a manifest.
/// Returns the manifest and the generated chunks as a vector of (Hash, Vec<u8>).
/// Note: In a production scenario for huge files, chunks would be streamed
/// directly to storage to avoid out-of-memory errors.
pub fn chunk_file<P: AsRef<Path>>(
    path: P,
    config: &ChunkConfig,
    mime_type: &str,
    storage_mode: StorageMode,
) -> Result<(StmManifest, Vec<(Hash, Vec<u8>)>), StmError> {
    let mut file = File::open(&path).map_err(|e| {
        StmError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    let metadata = file.metadata().map_err(|e| {
        StmError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    let original_size = metadata.len();
    let filename = path
        .as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut chunks = Vec::new();
    let mut descriptors = Vec::new();
    let mut leaves = Vec::new();

    let mut buffer = vec![0u8; config.chunk_size];
    let mut index = 0;

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;
        if bytes_read == 0 {
            break;
        }

        let chunk_data = &buffer[..bytes_read];
        let hash = hash_chunk(chunk_data);

        descriptors.push(ChunkDescriptor {
            index,
            hash,
            size: bytes_read as u64,
        });

        leaves.push(hash);
        chunks.push((hash, chunk_data.to_vec()));

        index += 1;
    }

    let merkle_root = build_merkle_root(leaves);

    let manifest = StmManifest::new(
        filename,
        mime_type.to_string(),
        original_size,
        config.chunk_size as u64,
        index,
        descriptors,
        merkle_root,
        storage_mode,
        unix_timestamp(),
    );

    Ok((manifest, chunks))
}

pub fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn verify_and_reassemble<P: AsRef<Path>, S: stm_storage::ChunkStore>(
    manifest: &StmManifest,
    store: &S,
    output_path: P,
) -> Result<(), StmError> {
    // 1. Verify manifest signature / content hash
    manifest.verify_signature()?;

    // 2. Validate chunk descriptors
    if manifest.total_chunks != manifest.chunks.len() as u64 {
        return Err(StmError::InvalidObject);
    }

    let mut expected_index = 0;
    let mut total_size_sum = 0;
    for chunk in &manifest.chunks {
        if chunk.index != expected_index {
            return Err(StmError::InvalidObject); // Non-contiguous or out-of-order
        }
        total_size_sum += chunk.size;
        expected_index += 1;
    }
    if total_size_sum != manifest.original_size {
        return Err(StmError::InvalidObject); // Size mismatch
    }

    // 3. Create temporary file
    let output_path = output_path.as_ref();
    let parent = output_path.parent().unwrap_or(Path::new(""));
    let mut temp_file = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        StmError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;

    // 4. Retrieve, verify, and write chunks
    let mut leaves = Vec::new();
    let mut actual_size_sum = 0;

    for chunk in &manifest.chunks {
        let chunk_data = store.get_chunk(&chunk.hash)?;

        if chunk_data.len() as u64 != chunk.size {
            return Err(StmError::InvalidObject);
        }

        if !verify_chunk(&chunk_data, &chunk.hash) {
            return Err(StmError::InvalidSignature);
        }

        temp_file.write_all(&chunk_data).map_err(|e| {
            StmError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?;

        leaves.push(chunk.hash);
        actual_size_sum += chunk.size;
    }

    // 5. Verify reconstructed Merkle root
    let reconstructed_root = build_merkle_root(leaves);
    if reconstructed_root != manifest.merkle_root {
        return Err(StmError::MerkleRootMismatch);
    }

    if actual_size_sum != manifest.original_size {
        return Err(StmError::InvalidObject);
    }

    // 6. Flush and atomic rename
    temp_file.flush().map_err(|e| {
        StmError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    temp_file.persist(output_path).map_err(|e| {
        StmError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;

    Ok(())
}
