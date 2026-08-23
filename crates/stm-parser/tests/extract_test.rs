use stm_core::ObjectFlags;
use stm_parser::{ParserMode, StmParser};
use stm_writer::ContainerBuilder;

#[test]
fn extracts_object_by_number() {
    let mut builder = ContainerBuilder::new();

    let mut oid0 = [0u8; 16];
    oid0[8..16].copy_from_slice(&0u64.to_be_bytes());

    let mut oid1 = [0u8; 16];
    oid1[8..16].copy_from_slice(&1u64.to_be_bytes());

    builder
        .add_object(oid0, 1, ObjectFlags(0), b"First object".to_vec())
        .unwrap();

    builder
        .add_object(oid1, 1, ObjectFlags(0), b"Second object".to_vec())
        .unwrap();

    let data = builder.build().unwrap();

    let parser = StmParser::new(ParserMode::Strict);

    let object = parser.extract_object_by_number(&data, 1).unwrap();

    assert_eq!(object, b"Second object");
}
