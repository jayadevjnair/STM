pub mod file_type;
pub mod metadata;

use crate::file_type::detect_mime_type;
use crate::metadata::StmFileMetadata;
use std::path::{Path, PathBuf};
use stm_core::{ObjectFlags, StmError, TYPE_FILE, TYPE_METADATA};
use stm_parser::{ParserMode, StmParser};
use stm_signature::SigningKey;
use stm_writer::ContainerBuilder;

/// Converts a normal file into an STM container with metadata.
pub fn convert_file_to_stmf(
    input_path: &Path,
    output_path: &Path,
    signing_key: Option<&SigningKey>,
) -> Result<(), StmError> {
    let file_bytes = std::fs::read(input_path)?;
    let filename = input_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let stm_bytes = convert_bytes_to_stmf(&file_bytes, &filename, signing_key)?;
    std::fs::write(output_path, stm_bytes)?;
    Ok(())
}

/// Converts raw file bytes and a filename into a serialized STM container.
/// Automatically detects MIME type from the file bytes.
pub fn convert_bytes_to_stmf(
    file_bytes: &[u8],
    filename: &str,
    signing_key: Option<&SigningKey>,
) -> Result<Vec<u8>, StmError> {
    let mime_type = detect_mime_type(file_bytes);
    let mut builder = ContainerBuilder::new();

    let metadata = StmFileMetadata {
        version: 1,
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        size: file_bytes.len() as u64,
        file_object_number: 1,
    };

    let metadata_bytes = serde_json::to_vec(&metadata).map_err(|_| StmError::InvalidObject)?;

    // Object 0: Metadata
    let oid_meta = [0u8; 16];
    builder.add_object(oid_meta, TYPE_METADATA, ObjectFlags::NONE, metadata_bytes)?;

    // Object 1: Original file raw bytes
    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&(1u64).to_be_bytes());
    builder.add_object(oid_file, TYPE_FILE, ObjectFlags::NONE, file_bytes.to_vec())?;

    if let Some(key) = signing_key {
        builder.build_signed(key)
    } else {
        builder.build()
    }
}

/// Extracts the original file from an STM container.
/// Strictly verifies Merkle tree integrity and digital signatures before extracting.
/// If container integrity or signature validation fails, extraction is rejected.
pub fn extract_original_file(
    stmf_path: &Path,
    output_directory: &Path,
) -> Result<PathBuf, StmError> {
    let stm_bytes = std::fs::read(stmf_path)?;
    let parser = StmParser::new(ParserMode::Strict);

    // 1. Verify container integrity & signature
    let summary = parser.parse_bytes(&stm_bytes)?;
    if !summary.merkle_valid {
        return Err(StmError::MerkleRootMismatch);
    }
    if summary.signed && summary.signature_valid != Some(true) {
        return Err(StmError::InvalidSignature);
    }

    // 2. Extract metadata at Object 0
    let oid_meta = [0u8; 16];
    let meta_bytes = parser.extract_object_by_oid(&stm_bytes, &oid_meta)?;
    let metadata: StmFileMetadata =
        serde_json::from_slice(&meta_bytes).map_err(|_| StmError::InvalidObject)?;

    // 3. Extract the original file object
    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&metadata.file_object_number.to_be_bytes());

    let file_data = parser.extract_object_by_oid(&stm_bytes, &oid_file)?;

    // 4. Ensure destination directory exists and write output
    std::fs::create_dir_all(output_directory)?;
    let output_path = output_directory.join(&metadata.filename);
    std::fs::write(&output_path, &file_data)?;

    Ok(output_path)
}
