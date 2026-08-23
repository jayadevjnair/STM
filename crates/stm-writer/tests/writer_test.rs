use stm_binary::{StmHeader, TOTAL_HEADER_SIZE};
use stm_core::ObjectFlags;
use stm_writer::ContainerBuilder;

#[test]
fn writer_builds_valid_container() {
    let mut builder = ContainerBuilder::new();

    builder
        .add_object([0x01; 16], 1, ObjectFlags(0), b"Hello STM".to_vec())
        .unwrap();

    builder
        .add_object([0x02; 16], 2, ObjectFlags(0), b"Second object".to_vec())
        .unwrap();

    let container = builder.build().unwrap();

    // Container must contain at least the header.
    assert!(container.len() >= TOTAL_HEADER_SIZE);

    // Header must be readable.
    let header = StmHeader::from_bytes(&container).unwrap();

    // Header length must match actual container length.
    assert_eq!(header.core.total_length, container.len() as u64);

    // We added two objects.
    assert_eq!(builder.object_count(), 2);
}

#[test]
fn writer_rejects_duplicate_oid() {
    let mut builder = ContainerBuilder::new();

    let oid = [0x01; 16];

    builder
        .add_object(oid, 1, ObjectFlags(0), b"First".to_vec())
        .unwrap();

    let result = builder.add_object(oid, 2, ObjectFlags(0), b"Second".to_vec());

    assert!(result.is_err());
}
