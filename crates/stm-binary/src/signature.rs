pub const SIGNATURE_ALGORITHM_ED25519: u32 = 1;

pub const SIGNATURE_ALGORITHM_SIZE: usize = 4;
pub const SIGNATURE_PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

pub const SIGNATURE_BLOCK_SIZE: usize =
    SIGNATURE_ALGORITHM_SIZE + SIGNATURE_PUBLIC_KEY_SIZE + SIGNATURE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureBlock {
    pub algorithm: u32,
    pub public_key: [u8; SIGNATURE_PUBLIC_KEY_SIZE],
    pub signature: [u8; SIGNATURE_SIZE],
}

impl SignatureBlock {
    pub fn new(
        public_key: [u8; SIGNATURE_PUBLIC_KEY_SIZE],
        signature: [u8; SIGNATURE_SIZE],
    ) -> Self {
        Self {
            algorithm: SIGNATURE_ALGORITHM_ED25519,
            public_key,
            signature,
        }
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_BLOCK_SIZE] {
        let mut out = [0u8; SIGNATURE_BLOCK_SIZE];

        out[0..4].copy_from_slice(&self.algorithm.to_be_bytes());
        out[4..36].copy_from_slice(&self.public_key);
        out[36..100].copy_from_slice(&self.signature);

        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, stm_core::StmError> {
        if data.len() < SIGNATURE_BLOCK_SIZE {
            return Err(stm_core::StmError::InvalidObject);
        }

        let algorithm = u32::from_be_bytes(
            data[0..4]
                .try_into()
                .map_err(|_| stm_core::StmError::InvalidObject)?,
        );

        if algorithm != SIGNATURE_ALGORITHM_ED25519 {
            return Err(stm_core::StmError::UnsupportedAlgorithm);
        }

        let mut public_key = [0u8; SIGNATURE_PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&data[4..36]);

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&data[36..100]);

        Ok(Self {
            algorithm,
            public_key,
            signature,
        })
    }
}
