use sha2::{Digest, Sha256};
use stm_core::Hash;

/// Hash arbitrary bytes using SHA-256.
pub fn hash_bytes(data: &[u8]) -> Hash {
    let result = Sha256::digest(data);

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);

    hash
}

/// ADI-014:
/// Empty Merkle tree root = SHA-256("")
pub fn empty_root() -> Hash {
    hash_bytes(b"")
}

/// ADI-019:
/// Leaf = Hash(complete canonical object bytes)
pub fn compute_leaf(object_bytes: &[u8]) -> Hash {
    hash_bytes(object_bytes)
}

/// ADI-016:
/// Build the Merkle tree.
///
/// If a level contains an odd number of nodes,
/// duplicate the final node.
pub fn build_merkle_root(leaves: Vec<Hash>) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }

    let mut current = leaves;

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);

        let mut index = 0;

        while index < current.len() {
            let left = current[index];

            let right = if index + 1 < current.len() {
                current[index + 1]
            } else {
                // ADI-016: duplicate last node
                current[index]
            };

            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);

            let result = hasher.finalize();

            let mut parent = [0u8; 32];
            parent.copy_from_slice(&result);

            next.push(parent);

            index += 2;
        }

        current = next;
    }

    current[0]
}
