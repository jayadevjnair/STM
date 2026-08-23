use stm_binary::TOTAL_HEADER_SIZE;
use stm_core::{ObjectFlags, StmError};
use stm_parser::{ParserMode, StmParser};
use stm_signature::generate_signing_key;
use stm_writer::ContainerBuilder;

#[test]
fn detects_tampered_signed_container() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object([1u8; 16], 1, ObjectFlags(0), b"Signed secure data".to_vec())
        .unwrap();

    let signing_key = generate_signing_key();

    let mut data = builder.build_signed(&signing_key).unwrap();

    // Directory format:
    // 8 bytes = object count
    // 40 bytes = one directory entry
    let payload_offset = TOTAL_HEADER_SIZE + 8 + 40;

    // Tamper with the first byte of the actual payload.
    data[payload_offset] ^= 0xFF;

    let parser = StmParser::new(ParserMode::Strict);
    let result = parser.parse_bytes(&data);

    assert!(matches!(
        result,
        Err(StmError::MerkleRootMismatch) | Err(StmError::InvalidSignature)
    ));
}
