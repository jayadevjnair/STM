use stm_core::{Hash, StmError};

pub mod signature;
pub use signature::*;

pub const MAGIC: [u8; 4] = *b"STMF";
pub const VERSION: u32 = 0x0001_0000;

pub const CORE_HEADER_SIZE: usize = 48;
pub const EXTENSION_HEADER_SIZE: usize = 24;
pub const TOTAL_HEADER_SIZE: usize = 72;

pub const FLAG_SIGNED: u64 = 0x0000_0000_0000_0001;

/// STM 1.0 fixed 48-byte core header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub total_length: u64,
    pub merkle_root: Hash,
}

/// STM 1.0 fixed 24-byte extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    pub reserved: [u8; 8],
    pub timestamp: u64,
    pub flags: u64,
}

/// Complete 72-byte STM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StmHeader {
    pub core: CoreHeader,
    pub extension: ExtensionHeader,
}

impl StmHeader {
    /// Create a new STM 1.0 header.
    pub fn new(total_length: u64, merkle_root: Hash) -> Self {
        Self {
            core: CoreHeader {
                magic: MAGIC,
                version: VERSION,
                total_length,
                merkle_root,
            },
            extension: ExtensionHeader {
                reserved: [0u8; 8],
                timestamp: 0,
                flags: 0,
            },
        }
    }

    /// Returns true if this container is marked as signed.
    pub fn is_signed(&self) -> bool {
        (self.extension.flags & FLAG_SIGNED) != 0
    }

    /// Set or clear the signed flag.
    pub fn set_signed(&mut self, signed: bool) {
        if signed {
            self.extension.flags |= FLAG_SIGNED;
        } else {
            self.extension.flags &= !FLAG_SIGNED;
        }
    }

    /// Serialize the header into exactly 72 bytes.
    pub fn to_bytes(&self) -> [u8; TOTAL_HEADER_SIZE] {
        let mut out = [0u8; TOTAL_HEADER_SIZE];

        // Core Header
        out[0..4].copy_from_slice(&self.core.magic);
        out[4..8].copy_from_slice(&self.core.version.to_be_bytes());
        out[8..16].copy_from_slice(&self.core.total_length.to_be_bytes());
        out[16..48].copy_from_slice(&self.core.merkle_root);

        // Extension Header
        out[48..56].copy_from_slice(&self.extension.reserved);
        out[56..64].copy_from_slice(&self.extension.timestamp.to_be_bytes());
        out[64..72].copy_from_slice(&self.extension.flags.to_be_bytes());

        out
    }

    /// Parse and validate a 72-byte STM header.
    pub fn from_bytes(data: &[u8]) -> Result<Self, StmError> {
        if data.len() < TOTAL_HEADER_SIZE {
            return Err(StmError::InvalidHeaderLength);
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        if magic != MAGIC {
            return Err(StmError::InvalidMagic);
        }

        let version = u32::from_be_bytes(
            data[4..8]
                .try_into()
                .map_err(|_| StmError::InvalidHeaderLength)?,
        );

        if version != VERSION {
            return Err(StmError::UnsupportedVersion);
        }

        let total_length = u64::from_be_bytes(
            data[8..16]
                .try_into()
                .map_err(|_| StmError::InvalidHeaderLength)?,
        );

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[16..48]);

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&data[48..56]);

        let timestamp = u64::from_be_bytes(
            data[56..64]
                .try_into()
                .map_err(|_| StmError::InvalidHeaderLength)?,
        );

        let flags = u64::from_be_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| StmError::InvalidHeaderLength)?,
        );

        Ok(Self {
            core: CoreHeader {
                magic,
                version,
                total_length,
                merkle_root,
            },
            extension: ExtensionHeader {
                reserved,
                timestamp,
                flags,
            },
        })
    }
}
