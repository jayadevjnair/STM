/// STM Object Identifier.
/// An OID is exactly 16 raw bytes.
pub type Oid = [u8; 16];

/// SHA-256 hash used by STM 1.0.
pub type Hash = [u8; 32];

/// STM Object Type identifier.
pub type ObjectType = u32;

pub const TYPE_METADATA: ObjectType = 1;
pub const TYPE_FILE: ObjectType = 2;

/// Object state identifier.
pub type ObjectState = u16;

/// Object flags stored as a 32-bit bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectFlags(pub u32);

impl ObjectFlags {
    pub const NONE: Self = Self(0);

    pub const COMPRESSED: Self = Self(1 << 0);
    pub const ENCRYPTED: Self = Self(1 << 1);
    pub const CHUNKED: Self = Self(1 << 2);
    pub const EXTERNAL: Self = Self(1 << 3);
    pub const CRITICAL: Self = Self(1 << 4);
    pub const READONLY: Self = Self(1 << 5);

    pub fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}
