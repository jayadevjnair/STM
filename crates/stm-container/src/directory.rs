use stm_core::{ObjectFlags, ObjectType, Oid, StmError};

/// One entry in the STM Directory.
///
/// The directory maps an object OID to its location
/// and metadata inside the STM container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub oid: Oid,
    pub obj_type: ObjectType,
    pub offset: u64,
    pub length: u64,
    pub flags: ObjectFlags,
}

/// STM Directory.
///
/// ADI-017: The object count is implicit from the
/// number of entries. No separate count field exists.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    pub entries: Vec<DirectoryEntry>,
}

impl Directory {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: DirectoryEntry) {
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sort entries lexicographically by raw OID bytes.
    pub fn sort_by_oid(&mut self) {
        self.entries.sort_by(|a, b| a.oid.cmp(&b.oid));
    }

    /// Find an object using binary search.
    pub fn find(&self, oid: &Oid) -> Option<&DirectoryEntry> {
        self.entries
            .binary_search_by(|entry| entry.oid.cmp(oid))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// Validate the frozen STM Directory rules.
    pub fn validate(&self, container_size: u64) -> Result<(), StmError> {
        for pair in self.entries.windows(2) {
            if pair[0].oid >= pair[1].oid {
                return Err(StmError::DirectoryOutOfOrder);
            }
        }

        for entry in &self.entries {
            let end = entry
                .offset
                .checked_add(entry.length)
                .ok_or(StmError::ObjectOutOfBounds)?;

            if end > container_size {
                return Err(StmError::ObjectOutOfBounds);
            }
        }

        Ok(())
    }
}
