use std::io::Cursor;
use stm_crypto::compute_leaf;
use stm_stream::compute_stream_hashes;

#[test]
fn test_streaming_hash_matches_compute_leaf() {
    // 1. Small data
    let small_data = b"STM v1.1.0 Streaming Test Data".to_vec();
    let direct_hash = compute_leaf(&small_data);
    let streamed_hash = compute_stream_hashes(Cursor::new(&small_data), 4).unwrap();
    assert_eq!(direct_hash, streamed_hash);

    // 2. Medium data across multiple chunk boundaries
    let medium_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let direct_hash_med = compute_leaf(&medium_data);
    let streamed_hash_med = compute_stream_hashes(Cursor::new(&medium_data), 1024).unwrap();
    assert_eq!(direct_hash_med, streamed_hash_med);

    // 3. Empty data
    let empty_data = Vec::new();
    let direct_empty = compute_leaf(&empty_data);
    let streamed_empty = compute_stream_hashes(Cursor::new(&empty_data), 64).unwrap();
    assert_eq!(direct_empty, streamed_empty);
}
