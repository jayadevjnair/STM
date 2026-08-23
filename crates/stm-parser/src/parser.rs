use stm_binary::{SignatureBlock, StmHeader, SIGNATURE_BLOCK_SIZE, TOTAL_HEADER_SIZE};
use stm_container::directory::{Directory, DirectoryEntry};
use stm_core::{Hash, ObjectFlags, ObjectType, Oid, StmError};
use stm_crypto::{build_merkle_root, compute_leaf};
use stm_signature::{verify_merkle_root, verifying_key_from_bytes};
#[derive(Debug, Clone, Copy)]
pub enum ParserMode {
    Strict,
}

#[derive(Debug)]
pub struct StmSummary {
    pub total_length: u64,
    pub object_count: usize,
    pub merkle_root: Hash,
    pub merkle_valid: bool,
    pub signed: bool,
    pub signature_valid: Option<bool>,
}

pub struct StmParser {
    mode: ParserMode,
}

impl StmParser {
    pub fn new(mode: ParserMode) -> Self {
        Self { mode }
    }
    pub fn extract_object_by_oid(&self, data: &[u8], oid: &Oid) -> Result<Vec<u8>, StmError> {
        let directory = self.parse_directory(data)?;

        directory.validate(data.len() as u64)?;

        let entry = directory.find(oid).ok_or(StmError::InvalidDirectory)?;

        let start: usize = entry
            .offset
            .try_into()
            .map_err(|_| StmError::ObjectOutOfBounds)?;

        let end_u64 = entry
            .offset
            .checked_add(entry.length)
            .ok_or(StmError::ObjectOutOfBounds)?;

        let end: usize = end_u64
            .try_into()
            .map_err(|_| StmError::ObjectOutOfBounds)?;

        if start > end || end > data.len() {
            return Err(StmError::ObjectOutOfBounds);
        }

        Ok(data[start..end].to_vec())
    }
    pub fn list_objects(&self, data: &[u8]) -> Result<Vec<DirectoryEntry>, StmError> {
        let directory = self.parse_directory(data)?;

        directory.validate(data.len() as u64)?;

        Ok(directory.entries)
    }

    pub fn extract_object_by_number(
        &self,
        data: &[u8],
        object_number: u64,
    ) -> Result<Vec<u8>, StmError> {
        // Parse the directory.
        let directory = self.parse_directory(data)?;

        // Convert the object number into the OID format used by the CLI.
        let mut oid = [0u8; 16];
        oid[8..16].copy_from_slice(&object_number.to_be_bytes());

        // Find the object.
        let entry = directory
            .entries
            .iter()
            .find(|entry| entry.oid == oid)
            .ok_or(StmError::InvalidDirectory)?;

        // Calculate safe bounds.
        let start: usize = entry
            .offset
            .try_into()
            .map_err(|_| StmError::ObjectOutOfBounds)?;

        let end_u64 = entry
            .offset
            .checked_add(entry.length)
            .ok_or(StmError::ObjectOutOfBounds)?;

        let end: usize = end_u64
            .try_into()
            .map_err(|_| StmError::ObjectOutOfBounds)?;

        if start > end || end > data.len() {
            return Err(StmError::ObjectOutOfBounds);
        }

        // Return a copy of the object payload.
        Ok(data[start..end].to_vec())
    }
    pub fn parse_bytes(&self, data: &[u8]) -> Result<StmSummary, StmError> {
        // 1. Check minimum container size.
        if data.len() < TOTAL_HEADER_SIZE {
            return Err(StmError::InvalidHeaderLength);
        }

        // 2. Parse STM header.
        let header = StmHeader::from_bytes(data)?;

        // 3. Header length must match actual container length.
        if header.core.total_length != data.len() as u64 {
            return Err(StmError::InvalidContainerLength);
        }

        // 4. Parse directory.
        let directory = self.parse_directory(data)?;

        // 5. Validate directory ordering and bounds.
        directory.validate(data.len() as u64)?;

        // 6. Recompute Merkle root from the objects.
        let calculated_root = self.compute_merkle(data, &directory)?;

        // 7. Compare calculated root with the header root.
        let merkle_valid = calculated_root == header.core.merkle_root;

        if !merkle_valid {
            return Err(StmError::MerkleRootMismatch);
        }

        // 8. Detect whether a signature block exists.
        //
        // The signature block is located after all objects.
        let objects_end = directory
            .entries
            .iter()
            .map(|entry| entry.offset + entry.length)
            .max()
            .unwrap_or(TOTAL_HEADER_SIZE as u64);

        let remaining_bytes = data.len() as u64 - objects_end;

        let (signed, signature_valid) = if remaining_bytes == SIGNATURE_BLOCK_SIZE as u64 {
            let signature_start = objects_end as usize;

            let signature_block = SignatureBlock::from_bytes(&data[signature_start..])?;

            let verifying_key = verifying_key_from_bytes(&signature_block.public_key)?;

            let valid = verify_merkle_root(
                &verifying_key,
                &header.core.merkle_root,
                &signature_block.signature,
            )
            .is_ok();

            (true, Some(valid))
        } else {
            (false, None)
        };

        let _ = self.mode;

        Ok(StmSummary {
            total_length: header.core.total_length,
            object_count: directory.len(),
            merkle_root: header.core.merkle_root,
            merkle_valid,
            signed,
            signature_valid,
        })
    }

    fn parse_directory(&self, data: &[u8]) -> Result<Directory, StmError> {
        let mut position = TOTAL_HEADER_SIZE;

        // Directory starts with an 8-byte u64 count.
        if data.len() < position + 8 {
            return Err(StmError::InvalidDirectory);
        }

        let count = u64::from_be_bytes(
            data[position..position + 8]
                .try_into()
                .map_err(|_| StmError::InvalidDirectory)?,
        );

        position += 8;

        // Protect against absurd counts and integer conversion issues.
        let count: usize = count.try_into().map_err(|_| StmError::InvalidDirectory)?;

        const ENTRY_SIZE: usize = 40;

        let directory_bytes = count
            .checked_mul(ENTRY_SIZE)
            .ok_or(StmError::InvalidDirectory)?;

        let directory_end = position
            .checked_add(directory_bytes)
            .ok_or(StmError::InvalidDirectory)?;

        if directory_end > data.len() {
            return Err(StmError::InvalidDirectory);
        }

        let mut directory = Directory::new();

        for _ in 0..count {
            // OID: 16 bytes
            let oid: Oid = data[position..position + 16]
                .try_into()
                .map_err(|_| StmError::InvalidDirectory)?;
            position += 16;

            // Object Type: 4 bytes
            let obj_type: ObjectType = u32::from_be_bytes(
                data[position..position + 4]
                    .try_into()
                    .map_err(|_| StmError::InvalidDirectory)?,
            );
            position += 4;

            // Offset: 8 bytes
            let offset = u64::from_be_bytes(
                data[position..position + 8]
                    .try_into()
                    .map_err(|_| StmError::InvalidDirectory)?,
            );
            position += 8;

            // Length: 8 bytes
            let length = u64::from_be_bytes(
                data[position..position + 8]
                    .try_into()
                    .map_err(|_| StmError::InvalidDirectory)?,
            );
            position += 8;

            // Flags: 4 bytes
            let flags = u32::from_be_bytes(
                data[position..position + 4]
                    .try_into()
                    .map_err(|_| StmError::InvalidDirectory)?,
            );
            position += 4;

            directory.add(DirectoryEntry {
                oid,
                obj_type,
                offset,
                length,
                flags: ObjectFlags(flags),
            });
        }

        Ok(directory)
    }

    fn compute_merkle(&self, data: &[u8], directory: &Directory) -> Result<Hash, StmError> {
        let mut leaves = Vec::with_capacity(directory.len());

        for entry in &directory.entries {
            let start: usize = entry
                .offset
                .try_into()
                .map_err(|_| StmError::ObjectOutOfBounds)?;

            let end_u64 = entry
                .offset
                .checked_add(entry.length)
                .ok_or(StmError::ObjectOutOfBounds)?;

            let end: usize = end_u64
                .try_into()
                .map_err(|_| StmError::ObjectOutOfBounds)?;

            if end > data.len() || start > end {
                return Err(StmError::ObjectOutOfBounds);
            }

            let payload = &data[start..end];

            let leaf = compute_leaf(payload);

            leaves.push(leaf);
        }

        Ok(build_merkle_root(leaves))
    }
}
