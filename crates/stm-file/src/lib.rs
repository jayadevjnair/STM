pub mod file_type;
pub mod metadata;

use crate::file_type::detect_mime_type;
use crate::metadata::StmFileMetadata;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use stm_binary::{SignatureBlock, StmHeader, SIGNATURE_BLOCK_SIZE, TOTAL_HEADER_SIZE};
use stm_container::directory::{Directory, DirectoryEntry};
use stm_core::{Hash, ObjectFlags, ObjectType, Oid, StmError, TYPE_FILE, TYPE_METADATA};
use stm_crypto::{build_merkle_root, compute_leaf};
use stm_parser::{ParserMode, StmParser, StmSummary};
use stm_signature::{
    public_key_bytes, sign_merkle_root, verify_merkle_root, verifying_key_from_bytes, SigningKey,
};
use stm_stream::chunk::DEFAULT_CHUNK_SIZE;
use stm_stream::progress::ProgressReporter;
use stm_stream::{compute_stream_hashes_with_progress, copy_with_progress};

/// Converts a normal file into an STM container with metadata (streaming / bounded memory).
pub fn convert_file_to_stmf(
    input_path: &Path,
    output_path: &Path,
    signing_key: Option<&SigningKey>,
) -> Result<(), StmError> {
    convert_file_to_stmf_streaming(input_path, output_path, signing_key, None)
}

/// Converts raw file bytes and a filename into a serialized STM container in memory.
pub fn convert_bytes_to_stmf(
    file_bytes: &[u8],
    filename: &str,
    signing_key: Option<&SigningKey>,
) -> Result<Vec<u8>, StmError> {
    use stm_writer::ContainerBuilder;

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

/// Converts a file to an STM container using a two-pass streaming architecture.
/// Bounded memory consumption: operates in 4 MiB buffer chunks.
pub fn convert_file_to_stmf_streaming(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    signing_key: Option<&SigningKey>,
    progress: Option<&dyn ProgressReporter>,
) -> Result<(), StmError> {
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let filename = input_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let file_size = std::fs::metadata(input_path)?.len();

    // -------------------------------------------------------------
    // Pass 1: Read magic bytes and incrementally compute object hash
    // -------------------------------------------------------------
    let mut file = File::open(input_path)?;
    let mut magic_header = [0u8; 16];
    let n = file.read(&mut magic_header)?;
    let mime_type = detect_mime_type(&magic_header[..n]);

    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE, file);

    let file_hash =
        compute_stream_hashes_with_progress(&mut reader, DEFAULT_CHUNK_SIZE, file_size, progress)?;

    // Construct Metadata JSON object (Object 0)
    let metadata = StmFileMetadata {
        version: 1,
        filename,
        mime_type: mime_type.to_string(),
        size: file_size,
        file_object_number: 1,
    };
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(|_| StmError::InvalidObject)?;
    let meta_hash = compute_leaf(&metadata_bytes);

    // Calculate Merkle Root: canonical OID order -> Object 0 (meta), Object 1 (file)
    let merkle_root = build_merkle_root(vec![meta_hash, file_hash]);

    // -------------------------------------------------------------
    // Pass 2: Assemble and stream the container
    // -------------------------------------------------------------
    const ENTRY_SIZE: usize = 40;
    let directory_size = 8u64 + (2 * ENTRY_SIZE as u64); // count (8) + 2 entries (80) = 88
    let object_base_offset = TOTAL_HEADER_SIZE as u64 + directory_size;

    let meta_offset = object_base_offset;
    let meta_len = metadata_bytes.len() as u64;

    let file_offset = meta_offset + meta_len;
    let file_len = file_size;

    let mut directory = Directory::new();
    let mut oid_meta = [0u8; 16];
    oid_meta[8..16].copy_from_slice(&(0u64).to_be_bytes());
    directory.add(DirectoryEntry {
        oid: oid_meta,
        obj_type: TYPE_METADATA,
        offset: meta_offset,
        length: meta_len,
        flags: ObjectFlags::NONE,
    });

    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&(1u64).to_be_bytes());
    directory.add(DirectoryEntry {
        oid: oid_file,
        obj_type: TYPE_FILE,
        offset: file_offset,
        length: file_len,
        flags: ObjectFlags::NONE,
    });

    let mut total_length = file_offset + file_len;

    // Build signature block if signing requested
    let sig_block_bytes = if let Some(key) = signing_key {
        let signature = sign_merkle_root(key, &merkle_root);
        let public_key = public_key_bytes(key);
        let sig_block = SignatureBlock::new(public_key, signature);
        let bytes = sig_block.to_bytes();
        total_length += bytes.len() as u64;
        Some(bytes)
    } else {
        None
    };

    let header = StmHeader::new(total_length, merkle_root);
    let header_bytes = header.to_bytes();

    // Serialize directory
    let mut dir_bytes = Vec::with_capacity(directory_size as usize);
    dir_bytes.extend_from_slice(&(2u64).to_be_bytes());
    for entry in &directory.entries {
        dir_bytes.extend_from_slice(&entry.oid);
        dir_bytes.extend_from_slice(&entry.obj_type.to_be_bytes());
        dir_bytes.extend_from_slice(&entry.offset.to_be_bytes());
        dir_bytes.extend_from_slice(&entry.length.to_be_bytes());
        dir_bytes.extend_from_slice(&entry.flags.0.to_be_bytes());
    }

    // Write to output file using BufWriter
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let out_file = File::create(output_path)?;
    let mut writer = BufWriter::with_capacity(DEFAULT_CHUNK_SIZE, out_file);

    writer.write_all(&header_bytes)?;
    writer.write_all(&dir_bytes)?;
    writer.write_all(&metadata_bytes)?;

    // Stream original file payload directly
    let mut in_file = File::open(input_path)?;
    in_file.seek(SeekFrom::Start(0))?;
    let in_reader = BufReader::with_capacity(DEFAULT_CHUNK_SIZE, in_file);

    copy_with_progress(
        in_reader,
        &mut writer,
        DEFAULT_CHUNK_SIZE,
        file_size,
        progress,
    )?;

    if let Some(sig_bytes) = sig_block_bytes {
        writer.write_all(&sig_bytes)?;
    }

    writer.flush()?;
    Ok(())
}

/// Verifies an STM container using streaming incremental validation.
pub fn verify_file_streaming(
    path: impl AsRef<Path>,
    chunk_size: usize,
    progress: Option<&dyn ProgressReporter>,
) -> Result<StmSummary, StmError> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let total_file_size = file.metadata()?.len();

    if total_file_size < TOTAL_HEADER_SIZE as u64 {
        return Err(StmError::InvalidHeaderLength);
    }

    // 1. Read and parse header
    let mut header_bytes = [0u8; TOTAL_HEADER_SIZE];
    file.read_exact(&mut header_bytes)?;
    let header = StmHeader::from_bytes(&header_bytes)?;

    if header.core.total_length != total_file_size {
        return Err(StmError::InvalidContainerLength);
    }

    // 2. Read directory
    let mut count_bytes = [0u8; 8];
    file.read_exact(&mut count_bytes)?;
    let count = u64::from_be_bytes(count_bytes) as usize;

    let mut directory = Directory::new();
    let mut entry_buf = [0u8; 40];

    for _ in 0..count {
        file.read_exact(&mut entry_buf)?;
        let mut oid = [0u8; 16];
        oid.copy_from_slice(&entry_buf[0..16]);
        let obj_type = u32::from_be_bytes(entry_buf[16..20].try_into().unwrap());
        let offset = u64::from_be_bytes(entry_buf[20..28].try_into().unwrap());
        let length = u64::from_be_bytes(entry_buf[28..36].try_into().unwrap());
        let flags = u32::from_be_bytes(entry_buf[36..40].try_into().unwrap());

        directory.add(DirectoryEntry {
            oid,
            obj_type,
            offset,
            length,
            flags: ObjectFlags(flags),
        });
    }

    directory.validate(total_file_size)?;

    // 3. Incrementally compute leaf hashes for all objects
    let mut leaves = Vec::with_capacity(directory.len());
    let mut processed_total = 0u64;

    for entry in &directory.entries {
        file.seek(SeekFrom::Start(entry.offset))?;
        let entry_reader = (&mut file).take(entry.length);

        let leaf_hash =
            compute_stream_hashes_with_progress(entry_reader, chunk_size, entry.length, None)?;
        leaves.push(leaf_hash);

        processed_total += entry.length;
        if let Some(reporter) = progress {
            reporter.on_progress(processed_total, total_file_size);
        }
    }

    let calculated_root = build_merkle_root(leaves);
    let merkle_valid = calculated_root == header.core.merkle_root;

    if !merkle_valid {
        return Err(StmError::MerkleRootMismatch);
    }

    // 4. Verify signature block if present
    let objects_end = directory
        .entries
        .iter()
        .map(|e| e.offset + e.length)
        .max()
        .unwrap_or(TOTAL_HEADER_SIZE as u64);

    let remaining_bytes = total_file_size - objects_end;
    let (signed, signature_valid) = if remaining_bytes == SIGNATURE_BLOCK_SIZE as u64 {
        file.seek(SeekFrom::Start(objects_end))?;
        let mut sig_buf = [0u8; SIGNATURE_BLOCK_SIZE];
        file.read_exact(&mut sig_buf)?;

        let sig_block = SignatureBlock::from_bytes(&sig_buf)?;
        let verifying_key = verifying_key_from_bytes(&sig_block.public_key)?;
        let valid = verify_merkle_root(
            &verifying_key,
            &header.core.merkle_root,
            &sig_block.signature,
        )
        .is_ok();
        (true, Some(valid))
    } else {
        (false, None)
    };

    Ok(StmSummary {
        total_length: header.core.total_length,
        object_count: directory.len(),
        merkle_root: header.core.merkle_root,
        merkle_valid,
        signed,
        signature_valid,
    })
}

/// Extracts the original file from an STM container.
pub fn extract_original_file(
    stmf_path: &Path,
    output_directory: &Path,
) -> Result<PathBuf, StmError> {
    extract_file_streaming(stmf_path, output_directory, None)
}

/// Extracts the original file from an STM container using streaming I/O.
/// Strictly verifies Merkle tree integrity and digital signatures before extracting.
/// If container integrity or signature validation fails, extraction is rejected and no file is left on disk.
pub fn extract_file_streaming(
    container_path: impl AsRef<Path>,
    output_directory: impl AsRef<Path>,
    progress: Option<&dyn ProgressReporter>,
) -> Result<PathBuf, StmError> {
    let container_path = container_path.as_ref();
    let output_directory = output_directory.as_ref();

    // 1. Verify container integrity & signature first
    let summary = verify_file_streaming(container_path, DEFAULT_CHUNK_SIZE, progress)?;
    if !summary.merkle_valid {
        return Err(StmError::MerkleRootMismatch);
    }
    if summary.signed && summary.signature_valid != Some(true) {
        return Err(StmError::InvalidSignature);
    }

    // 2. Read metadata at Object 0
    let mut file = File::open(container_path)?;
    let mut count_buf = [0u8; 8];
    file.seek(SeekFrom::Start(TOTAL_HEADER_SIZE as u64))?;
    file.read_exact(&mut count_buf)?;
    let count = u64::from_be_bytes(count_buf) as usize;

    let mut directory = Directory::new();
    let mut entry_buf = [0u8; 40];

    for _ in 0..count {
        file.read_exact(&mut entry_buf)?;
        let mut oid = [0u8; 16];
        oid.copy_from_slice(&entry_buf[0..16]);
        let obj_type = u32::from_be_bytes(entry_buf[16..20].try_into().unwrap());
        let offset = u64::from_be_bytes(entry_buf[20..28].try_into().unwrap());
        let length = u64::from_be_bytes(entry_buf[28..36].try_into().unwrap());
        let flags = u32::from_be_bytes(entry_buf[36..40].try_into().unwrap());

        directory.add(DirectoryEntry {
            oid,
            obj_type,
            offset,
            length,
            flags: ObjectFlags(flags),
        });
    }

    let mut oid_meta = [0u8; 16];
    let meta_entry = directory
        .find(&oid_meta)
        .ok_or(StmError::InvalidDirectory)?;

    file.seek(SeekFrom::Start(meta_entry.offset))?;
    let mut meta_bytes = vec![0u8; meta_entry.length as usize];
    file.read_exact(&mut meta_bytes)?;

    let metadata: StmFileMetadata =
        serde_json::from_slice(&meta_bytes).map_err(|_| StmError::InvalidObject)?;

    // 3. Locate file object
    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&metadata.file_object_number.to_be_bytes());
    let file_entry = directory
        .find(&oid_file)
        .ok_or(StmError::InvalidDirectory)?;

    // 4. Stream extract to temporary file first
    std::fs::create_dir_all(output_directory)?;
    let temp_path = output_directory.join(format!("{}.tmp", metadata.filename));
    let final_path = output_directory.join(&metadata.filename);

    file.seek(SeekFrom::Start(file_entry.offset))?;
    let payload_reader = (&mut file).take(file_entry.length);

    let temp_file = File::create(&temp_path)?;
    let mut writer = BufWriter::with_capacity(DEFAULT_CHUNK_SIZE, temp_file);

    copy_with_progress(
        payload_reader,
        &mut writer,
        DEFAULT_CHUNK_SIZE,
        file_entry.length,
        progress,
    )?;

    // Atomic rename after complete successful extraction
    std::fs::rename(&temp_path, &final_path)?;

    Ok(final_path)
}
