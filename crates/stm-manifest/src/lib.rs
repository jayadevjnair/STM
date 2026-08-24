use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use stm_core::{Hash, StmError};
use stm_crypto::hash_bytes;
use stm_signature::{
    generate_signing_key, load_public_key, load_signing_key, sign_merkle_root, verify_merkle_root,
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};
use uuid::Uuid;

pub const MANIFEST_DOMAIN_SEPARATOR: &[u8] = b"STM-MANIFEST-V2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageMode {
    Embedded,
    Remote,
    Hybrid,
}

impl StorageMode {
    fn to_u8(&self) -> u8 {
        match self {
            StorageMode::Embedded => 0,
            StorageMode::Remote => 1,
            StorageMode::Hybrid => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkDescriptor {
    pub index: u64,
    #[serde(with = "hex_hash")]
    pub hash: Hash,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StmManifest {
    pub version: String,
    pub manifest_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,

    pub filename: String,
    pub mime_type: String,
    pub original_size: u64,

    pub chunk_size: u64,
    pub total_chunks: u64,

    pub chunks: Vec<ChunkDescriptor>,
    #[serde(with = "hex_hash")]
    pub merkle_root: Hash,

    pub storage_mode: StorageMode,
    pub created_at: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

impl StmManifest {
    pub fn new(
        filename: String,
        mime_type: String,
        original_size: u64,
        chunk_size: u64,
        total_chunks: u64,
        chunks: Vec<ChunkDescriptor>,
        merkle_root: Hash,
        storage_mode: StorageMode,
        created_at: u64,
    ) -> Self {
        let mut manifest = Self {
            version: "2.0".to_string(),
            manifest_id: "".to_string(), // computed later
            transfer_id: Some(Uuid::new_v4().to_string()),
            filename,
            mime_type,
            original_size,
            chunk_size,
            total_chunks,
            chunks,
            merkle_root,
            storage_mode,
            created_at,
            public_key: None,
            signature: None,
            signature_algorithm: None,
        };

        manifest.manifest_id = hex::encode(manifest.content_hash());
        manifest
    }

    fn encode_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        encoded.extend_from_slice(bytes);
        encoded
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MANIFEST_DOMAIN_SEPARATOR);
        buf.extend_from_slice(&Self::encode_string(&self.version));
        buf.push(self.storage_mode.to_u8());
        buf.extend_from_slice(&Self::encode_string(&self.filename));
        buf.extend_from_slice(&Self::encode_string(&self.mime_type));
        buf.extend_from_slice(&self.original_size.to_le_bytes());
        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf.extend_from_slice(&self.total_chunks.to_le_bytes());

        for chunk in &self.chunks {
            buf.extend_from_slice(&chunk.index.to_le_bytes());
            buf.extend_from_slice(&chunk.hash);
            buf.extend_from_slice(&chunk.size.to_le_bytes());
        }

        buf.extend_from_slice(&self.merkle_root);
        buf
    }

    pub fn content_hash(&self) -> Hash {
        hash_bytes(&self.canonical_bytes())
    }

    pub fn sign(&mut self, private_key_bytes: &[u8; 32]) -> Result<(), StmError> {
        let signing_key = load_signing_key(private_key_bytes)?;
        let content_hash = self.content_hash();

        let signature: Signature = signing_key.sign(&content_hash);

        self.manifest_id = hex::encode(content_hash);
        self.public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
        self.signature = Some(hex::encode(signature.to_bytes()));
        self.signature_algorithm = Some("ed25519".to_string());

        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), StmError> {
        let content_hash = self.content_hash();
        if self.manifest_id != hex::encode(content_hash) {
            return Err(StmError::InvalidSignature); // Or create a new variant ManifestIdMismatch
        }

        if let (Some(pub_key_hex), Some(sig_hex)) = (&self.public_key, &self.signature) {
            let pub_key_bytes = hex::decode(pub_key_hex).map_err(|_| StmError::InvalidPublicKey)?;
            let verifying_key = load_public_key(&pub_key_bytes)?;

            let sig_bytes = hex::decode(sig_hex).map_err(|_| StmError::InvalidSignature)?;
            let signature = Signature::from_bytes(
                sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StmError::InvalidSignature)?,
            );

            verifying_key
                .verify(&content_hash, &signature)
                .map_err(|_| StmError::InvalidSignature)?;
        }

        Ok(())
    }
}

/// Helper module to serialize/deserialize `Hash` as hex strings
pub mod hex_hash {
    use super::*;

    pub fn serialize<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(hash);
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor;

        impl<'de> serde::de::Visitor<'de> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-character hex string representing a SHA-256 hash")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("hash must be 32 bytes long"));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                Ok(hash)
            }
        }

        deserializer.deserialize_str(HashVisitor)
    }
}
