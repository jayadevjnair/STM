use stm_binary::{StmHeader, TOTAL_HEADER_SIZE};

#[test]
fn header_is_exactly_72_bytes() {
    let root = [0xAA; 32];
    let header = StmHeader::new(1000, root);

    let bytes = header.to_bytes();

    assert_eq!(bytes.len(), TOTAL_HEADER_SIZE);
    assert_eq!(bytes.len(), 72);
}

#[test]
fn header_round_trip() {
    let root = [0xAB; 32];
    let header = StmHeader::new(5000, root);

    let bytes = header.to_bytes();
    let parsed = StmHeader::from_bytes(&bytes).unwrap();

    assert_eq!(parsed, header);
}

#[test]
fn invalid_magic_is_rejected() {
    let data = [0u8; 72];

    let result = StmHeader::from_bytes(&data);

    assert!(result.is_err());
}