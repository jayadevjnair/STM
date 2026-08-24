use std::fs;
use stm_file::{convert_file_to_stmf, extract_original_file};
use tempfile::tempdir;

#[test]
fn test_file_conversion_and_extraction_round_trip() {
    let dir = tempdir().unwrap();
    let original_file = dir.path().join("photo.png");
    let stmf_file = dir.path().join("photo.stmf");
    let output_dir = dir.path().join("extracted");

    // Real PNG magic bytes + payload
    let mut png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    png_data.extend_from_slice(b"SAMPLE_PNG_IMAGE_PIXEL_DATA_1234567890");
    fs::write(&original_file, &png_data).unwrap();

    // 1. Convert to .stmf
    convert_file_to_stmf(&original_file, &stmf_file, None).expect("Conversion should succeed");

    // 2. Extract original file
    let extracted_path =
        extract_original_file(&stmf_file, &output_dir).expect("Extraction should succeed");

    // 3. Verify path and filename
    assert_eq!(extracted_path, output_dir.join("photo.png"));

    // 4. Verify byte-for-byte exact match
    let extracted_data = fs::read(&extracted_path).unwrap();
    assert_eq!(png_data, extracted_data);
}
