pub mod chunk;
pub mod progress;
pub mod reader;
pub mod writer;

pub use chunk::DEFAULT_CHUNK_SIZE;
pub use progress::{
    CallbackProgressReporter, CliProgressBar, NoopProgressReporter, ProgressReporter,
    ProgressUpdate,
};
pub use reader::StreamReader;
pub use writer::copy_with_progress;

use sha2::{Digest, Sha256};
use std::io::Read;
use stm_core::{Hash, StmError};

/// Incrementally computes the exact SHA-256 hash of a stream in bounded-memory chunks.
/// This matches byte-for-byte with the output of `stm_crypto::compute_leaf()` on the full payload.
pub fn compute_stream_hashes<R: Read>(reader: R, chunk_size: usize) -> Result<Hash, StmError> {
    compute_stream_hashes_with_progress(reader, chunk_size, 0, None)
}

/// Incrementally computes the exact SHA-256 hash of a stream with progress reporting.
pub fn compute_stream_hashes_with_progress<R: Read>(
    mut reader: R,
    chunk_size: usize,
    total_bytes: u64,
    progress: Option<&dyn ProgressReporter>,
) -> Result<Hash, StmError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; chunk_size.max(1)];
    let mut processed = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        processed += n as u64;
        if let Some(reporter) = progress {
            reporter.on_progress(processed, total_bytes);
        }
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}
