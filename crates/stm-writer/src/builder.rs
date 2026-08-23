use stm_binary::{SignatureBlock, StmHeader, TOTAL_HEADER_SIZE};
use stm_container::directory::{Directory, DirectoryEntry};
use stm_core::{Hash, ObjectFlags, ObjectType, Oid, StmError};
use stm_crypto::{build_merkle_root, compute_leaf};
use stm_signature::{generate_signing_key, public_key_bytes, sign_merkle_root};

#[derive(Debug, Clone)]
pub struct PendingObject {
    pub oid: Oid,
    pub obj_type: ObjectType,
    pub flags: ObjectFlags,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct ContainerBuilder {
    objects: Vec<PendingObject>,
}

impl ContainerBuilder {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
        }
    }

    /// Build a signed STM container.
    pub fn build_signed(&mut self) -> Result<Vec<u8>, StmError> {
        // Build the unsigned container.
        let mut container = self.build()?;

        // Generate signing key.
        let signing_key = generate_signing_key();

        // Read the header.
        let mut header = StmHeader::from_bytes(&container)?;

        // Sign the Merkle root.
        let signature = sign_merkle_root(&signing_key, &header.core.merkle_root);

        // Get public key.
        let public_key = public_key_bytes(&signing_key);

        // Create signature block.
        let signature_block = SignatureBlock::new(public_key, signature);

        let signature_bytes = signature_block.to_bytes();

        // Update container length.
        header.core.total_length += signature_bytes.len() as u64;

        // Replace header.
        let header_bytes = header.to_bytes();
        container[0..TOTAL_HEADER_SIZE].copy_from_slice(&header_bytes);

        // Append signature.
        container.extend_from_slice(&signature_bytes);

        Ok(container)
    }

    pub fn add_object(
        &mut self,
        oid: Oid,
        obj_type: ObjectType,
        flags: ObjectFlags,
        payload: Vec<u8>,
    ) -> Result<(), StmError> {
        // Prevent duplicate object IDs.
        if self.objects.iter().any(|object| object.oid == oid) {
            return Err(StmError::DuplicateOid);
        }

        self.objects.push(PendingObject {
            oid,
            obj_type,
            flags,
            payload,
        });

        Ok(())
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    fn sort_objects(&mut self) {
        self.objects.sort_by(|a, b| a.oid.cmp(&b.oid));
    }

    /// Serialize the directory.
    ///
    /// Format:
    /// count: u64
    /// each entry:
    ///   oid: [u8; 16]
    ///   type: u32
    ///   offset: u64
    ///   length: u64
    ///   flags: u32
    fn serialize_directory(directory: &Directory) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&(directory.entries.len() as u64).to_be_bytes());

        for entry in &directory.entries {
            out.extend_from_slice(&entry.oid);
            out.extend_from_slice(&entry.obj_type.to_be_bytes());
            out.extend_from_slice(&entry.offset.to_be_bytes());
            out.extend_from_slice(&entry.length.to_be_bytes());
            out.extend_from_slice(&entry.flags.0.to_be_bytes());
        }

        out
    }

    fn build_directory(&self, object_base_offset: u64) -> Directory {
        let mut directory = Directory::new();
        let mut current_offset = object_base_offset;

        for object in &self.objects {
            let length = object.payload.len() as u64;

            directory.add(DirectoryEntry {
                oid: object.oid,
                obj_type: object.obj_type,
                offset: current_offset,
                length,
                flags: object.flags,
            });

            current_offset += length;
        }

        directory
    }

    pub fn compute_merkle_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .objects
            .iter()
            .map(|object| compute_leaf(&object.payload))
            .collect();

        build_merkle_root(leaves)
    }

    /// Build a complete unsigned STM container.
    pub fn build(&mut self) -> Result<Vec<u8>, StmError> {
        // Canonical object ordering.
        self.sort_objects();

        // Directory size:
        // count = 8 bytes
        // each entry = 40 bytes
        let directory_size = 8u64 + (self.objects.len() as u64 * 40);

        // Objects begin after header and directory.
        let object_base_offset = TOTAL_HEADER_SIZE as u64 + directory_size;

        // Build directory.
        let directory = self.build_directory(object_base_offset);

        // Serialize directory.
        let directory_bytes = Self::serialize_directory(&directory);

        // Compute Merkle root.
        let merkle_root = self.compute_merkle_root();

        // Calculate object data size.
        let object_bytes_size: u64 = self
            .objects
            .iter()
            .map(|object| object.payload.len() as u64)
            .sum();

        // Calculate total container size.
        let total_length =
            TOTAL_HEADER_SIZE as u64 + directory_bytes.len() as u64 + object_bytes_size;

        // Create header.
        let header = StmHeader::new(total_length, merkle_root);

        let header_bytes = header.to_bytes();

        // Assemble container.
        let mut out = Vec::with_capacity(total_length as usize);

        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&directory_bytes);

        for object in &self.objects {
            out.extend_from_slice(&object.payload);
        }

        Ok(out)
    }
}
