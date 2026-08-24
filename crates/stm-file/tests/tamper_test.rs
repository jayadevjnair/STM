use std::fs;
use stm_file::{convert_file_to_stmf, extract_original_file};
use stm_signature::generate_signing_key;
use tempfile::tempdir;

#[test]
fn test_tampered_stmf_fails_extraction() {
    let dir = tempdir().unwrap();
    let original_file = dir.path().join("secure_document.pdf");
    let stmf_file = dir.path().join("secure_document.stmf");
    let output_dir = dir.path().join("extracted");

    let pdf_data = b"%PDF-1.7 confidential report data";
    fs::write(&original_file, pdf_data).unwrap();

    let signing_key = generate_signing_key();

    // 1. Convert to signed STMF
    convert_file_to_stmf(&original_file, &stmf_file, Some(&signing_key))
        .expect("Conversion should succeed");

    // 2. Tamper with the container bytes (flip bits in the payload)
    let mut stmf_bytes = fs::read(&stmf_file).unwrap();
    let mid = stmf_bytes.len() / 2;
    stmf_bytes[mid] ^= 0xFF; // modify byte
    fs::write(&stmf_file, &stmf_bytes).unwrap();

    // 3. Attempt extraction - MUST FAIL
    let result = extract_original_file(&stmf_file, &output_dir);
    assert!(
        result.is_err(),
        "Extraction of a tampered STM container must be rejected"
    );

    // 4. Ensure no file was created in output_dir
    let expected_output = output_dir.join("secure_document.pdf");
    assert!(
        !expected_output.exists(),
        "Tampered content must never be written to disk"
    );
}
