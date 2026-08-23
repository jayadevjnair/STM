use stm_core::{ObjectFlags, StmError};
use stm_parser::{ParserMode, StmParser};
use stm_writer::ContainerBuilder;

#[test]
fn detects_tampered_signed_container() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object(
            [1u8; 16],
            1,
            ObjectFlags(0),
            b"Signed secure data".to_vec(),
        )
        .unwrap();

    let mut data = builder.build_signed().unwrap();

    // Tamper with the signed container.
    // Change a byte in the payload area, not the signature block.
    let payload_offset = 120;
    data[payload_offset] ^= 0xFF;

    let parser = StmParser::new(ParserMode::Strict);
    let result = parser.parse_bytes(&data);

    assert!(matches!(
        result,
        Err(StmError::MerkleRootMismatch)
            | Err(StmError::InvalidSignature)
    ));
}