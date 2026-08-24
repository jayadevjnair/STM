use stm_core::Hash;
use crate::error::ServerError;

pub fn validate_hash_param(hash_str: &str) -> Result<Hash, ServerError> {
    if hash_str.len() != 64 {
        return Err(ServerError::BadRequest("Hash must be exactly 64 characters".to_string()));
    }

    let bytes = hex::decode(hash_str).map_err(|_| {
        ServerError::BadRequest("Hash contains invalid hexadecimal characters".to_string())
    })?;

    if bytes.len() != 32 {
        return Err(ServerError::BadRequest("Hash must be exactly 32 bytes".to_string()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}
