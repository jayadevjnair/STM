use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StmError {
    #[error("invalid STM magic bytes")]
    InvalidMagic,

    #[error("unsupported STM version")]
    UnsupportedVersion,

    #[error("invalid header length")]
    InvalidHeaderLength,

    #[error("invalid container length")]
    InvalidContainerLength,

    #[error("invalid object offset")]
    InvalidOffset,
    #[error("invalid digital signature")]
    InvalidSignature,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("object exceeds container bounds")]
    ObjectOutOfBounds,

    #[error("directory entries are not in canonical OID order")]
    DirectoryOutOfOrder,

    #[error("duplicate object OID")]
    DuplicateOid,

    #[error("invalid directory")]
    InvalidDirectory,

    #[error("Merkle root mismatch")]
    MerkleRootMismatch,

    #[error("invalid object")]
    InvalidObject,

    #[error("unsupported object type")]
    UnsupportedObjectType,

    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,

    #[error("invalid canonical encoding")]
    InvalidCanonicalEncoding,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
