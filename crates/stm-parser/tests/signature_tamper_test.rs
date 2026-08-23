use stm_binary::SIGNATURE_BLOCK_SIZE;
use stm_core::{ObjectFlags, StmError};
use stm_parser::{ParserMode, StmParser};
use stm_signature::generate_signing_key;
use stm_writer::ContainerBuilder;

#[test]
fn detects_tampered_signature() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object(
            [2u8; 16],
            1,
            ObjectFlags(0),
            b"Signature protected data".to_vec(),
        )
        .unwrap();

    let signing_key = generate_signing_key();

    let mut data = builder.build_signed(&signing_key).unwrap();

    // Signature block is at the end of the container.
    let signature_start = data.len() - SIGNATURE_BLOCK_SIZE;

    // Modify the last byte, which is inside the signature block.
    let tamper_offset = data.len() - 1;

    assert!(tamper_offset >= signature_start);

    data[tamper_offset] ^= 0xFF;

    let parser = StmParser::new(ParserMode::Strict);
    let result = parser.parse_bytes(&data);

    // Merkle data is unchanged, but the signature must fail.
    match result {
        Ok(summary) => {
            assert!(summary.signed);
            assert_eq!(summary.merkle_valid, true);
            assert_eq!(summary.signature_valid, Some(false));
        }

        Err(StmError::InvalidSignature) => {}

        Err(error) => panic!("Unexpected error: {:?}", error),
    }
}
