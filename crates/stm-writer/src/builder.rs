use stm_binary::{StmHeader, TOTAL_HEADER_SIZE};
use stm_container::directory::{Directory, DirectoryEntry};
use stm_core::{Hash, ObjectFlags, ObjectType, Oid, StmError};
use stm_crypto::{build_merkle_root, compute_leaf};

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

    pub fn add_object(
        &mut self,
        oid: Oid,
        obj_type: ObjectType,
        flags: ObjectFlags,
        payload: Vec<u8>,
    ) -> Result<(), StmError> {
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
    /// count      : u64
    /// each entry :
    ///   oid      : [u8; 16]
    ///   type     : u32
    ///   offset   : u64
    ///   length   : u64
    ///   flags    : u32
    ///
    /// Each entry = 40 bytes.
    fn serialize_directory(directory: &Directory) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&(directory.entries.len() as u64).to_be_bytes());

        for entry in &directory.entries {
            out.extend_from_slice(&entry.oid);
            out.extend_from_slice(&entry.obj_type.to_be_bytes());            out.extend_from_slice(&entry.offset.to_be_bytes());
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

    /// Build a complete STM container.
    pub fn build(&mut self) -> Result<Vec<u8>, StmError> {
        // 1. Canonical object ordering.
        self.sort_objects();

        // 2. We know the directory size because every entry has
        // a fixed binary size.
        //
        // count = 8 bytes
        // entry = 40 bytes
        let directory_size = 8u64 + (self.objects.len() as u64 * 40);

        // 3. Objects begin after header + directory.
        let object_base_offset =
            TOTAL_HEADER_SIZE as u64 + directory_size;

        // 4. Build directory with final object offsets.
        let directory = self.build_directory(object_base_offset);

        // 5. Serialize directory.
        let directory_bytes = Self::serialize_directory(&directory);

        // 6. Compute Merkle root.
        let merkle_root = self.compute_merkle_root();

        // 7. Calculate total container size.
        let object_bytes_size: u64 = self
            .objects
            .iter()
            .map(|object| object.payload.len() as u64)
            .sum();

        let total_length =
            TOTAL_HEADER_SIZE as u64
            + directory_bytes.len() as u64
            + object_bytes_size;

        // 8. Create STM header.
        let header = StmHeader::new(total_length, merkle_root);
        let header_bytes = header.to_bytes();

        // 9. Assemble the final container.
        let mut out = Vec::with_capacity(total_length as usize);

        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&directory_bytes);

        for object in &self.objects {
            out.extend_from_slice(&object.payload);
        }

        Ok(out)
    }
}