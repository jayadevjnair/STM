use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use stm_stream::{compute_stream_hashes, DEFAULT_CHUNK_SIZE};
use tempfile::tempdir;

#[test]
fn test_large_file_streaming_hash_50mb() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("large_50mb.bin");

    // Write 50 MiB in 1 MiB chunks deterministically
    {
        let file = File::create(&file_path).unwrap();
        let mut writer = BufWriter::new(file);
        let block = vec![0xA5u8; 1024 * 1024]; // 1 MiB
        for _ in 0..50 {
            writer.write_all(&block).unwrap();
        }
        writer.flush().unwrap();
    }

    // Stream hash using 4 MiB chunks
    let file = File::open(&file_path).unwrap();
    let reader = BufReader::new(file);
    let hash = compute_stream_hashes(reader, DEFAULT_CHUNK_SIZE).unwrap();

    // Verify hash is non-zero
    assert_ne!(hash, [0u8; 32]);
}
