use stm_core::ObjectFlags;
use stm_parser::{ParserMode, StmParser};
use stm_writer::ContainerBuilder;

#[test]
fn detects_tampered_object_data() {
    let mut builder = ContainerBuilder::new();

    let oid = [1u8; 16];

    builder
        .add_object(oid, 1, ObjectFlags(0), b"Original secure data".to_vec())
        .unwrap();

    let mut data = builder.build().unwrap();

    // Tamper with the final byte of the object payload.
    let last = data.len() - 1;
    data[last] ^= 0xFF;

    let parser = StmParser::new(ParserMode::Strict);

    let result = parser.parse_bytes(&data);

    assert!(result.is_err());
}
