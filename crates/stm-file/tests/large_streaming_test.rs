use std::fs::File;
use std::io::{BufWriter, Write};
use stm_file::{convert_file_to_stmf_streaming, extract_file_streaming, verify_file_streaming};
use stm_signature::generate_signing_key;
use stm_stream::chunk::DEFAULT_CHUNK_SIZE;
use tempfile::tempdir;

#[test]
fn test_streaming_large_file_round_trip() {
    let dir = tempdir().unwrap();
    let original_file = dir.path().join("video.mp4");
    let stmf_file = dir.path().join("video.stmf");
    let output_dir = dir.path().join("extracted");

    // Create a 20 MiB synthetic video file with genuine MP4 magic box header
    {
        let file = File::create(&original_file).unwrap();
        let mut writer = BufWriter::new(file);

        // MP4 signature header: 0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p'
        let mut header = vec![0x00, 0x00, 0x00, 0x18];
        header.extend_from_slice(b"ftypisom");
        writer.write_all(&header).unwrap();

        // 20 chunks of 1 MiB each
        let chunk = vec![0x37u8; 1024 * 1024];
        for _ in 0..20 {
            writer.write_all(&chunk).unwrap();
        }
        writer.flush().unwrap();
    }

    let signing_key = generate_signing_key();

    // 1. Streaming convert
    convert_file_to_stmf_streaming(&original_file, &stmf_file, Some(&signing_key), None)
        .expect("Streaming conversion should succeed");

    // 2. Streaming verify
    let summary = verify_file_streaming(&stmf_file, DEFAULT_CHUNK_SIZE, None)
        .expect("Streaming verification should succeed");
    assert!(summary.merkle_valid);
    assert!(summary.signed);
    assert_eq!(summary.signature_valid, Some(true));

    // 3. Streaming extract
    let extracted_path = extract_file_streaming(&stmf_file, &output_dir, None)
        .expect("Streaming extraction should succeed");

    assert_eq!(extracted_path, output_dir.join("video.mp4"));

    // 4. Verify exact byte-for-byte equality
    let orig_meta = std::fs::metadata(&original_file).unwrap();
    let ext_meta = std::fs::metadata(&extracted_path).unwrap();
    assert_eq!(orig_meta.len(), ext_meta.len());

    let orig_hash =
        stm_stream::compute_stream_hashes(File::open(&original_file).unwrap(), DEFAULT_CHUNK_SIZE)
            .unwrap();
    let ext_hash =
        stm_stream::compute_stream_hashes(File::open(&extracted_path).unwrap(), DEFAULT_CHUNK_SIZE)
            .unwrap();

    assert_eq!(orig_hash, ext_hash);
}
