use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StmFileMetadata {
    pub version: u32,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub file_object_number: u64,
}

impl StmFileMetadata {
    pub fn new(filename: String, mime_type: String, size: u64, file_object_number: u64) -> Self {
        Self {
            version: 1,
            filename,
            mime_type,
            size,
            file_object_number,
        }
    }
}
