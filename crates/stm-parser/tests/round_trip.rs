use stm_core::ObjectFlags;
use stm_parser::{ParserMode, StmParser};
use stm_writer::ContainerBuilder;

#[test]
fn writer_and_parser_round_trip() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object(
            [0x01; 16],
            1,
            ObjectFlags(0),
            b"Hello STM".to_vec(),
        )
        .unwrap();

    builder
        .add_object(
            [0x02; 16],
            2,
            ObjectFlags(0),
            b"Second STM object".to_vec(),
        )
        .unwrap();

    // Build the STM container.
    let container = builder.build().unwrap();

    // Parse it back.
    let parser = StmParser::new(ParserMode::Strict);
    let summary = parser.parse_bytes(&container).unwrap();

    // Verify the complete round trip.
    assert_eq!(summary.object_count, 2);
    assert_eq!(summary.total_length, container.len() as u64);
    assert!(summary.merkle_valid);
}

#[test]
fn parser_detects_tampered_object() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object(
            [0x01; 16],
            1,
            ObjectFlags(0),
            b"Original data".to_vec(),
        )
        .unwrap();

    let mut container = builder.build().unwrap();

    // Modify the last byte of the object payload.
    let last = container.len() - 1;
    container[last] ^= 0xFF;

    let parser = StmParser::new(ParserMode::Strict);
    let result = parser.parse_bytes(&container);

    // Tampering must be detected through the Merkle root.
    assert!(result.is_err());
}