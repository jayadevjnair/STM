use stm_file::metadata::StmFileMetadata;

#[test]
fn test_metadata_serialization_round_trip() {
    let metadata = StmFileMetadata {
        version: 1,
        filename: "photo.png".to_string(),
        mime_type: "image/png".to_string(),
        size: 2483921,
        file_object_number: 1,
    };

    let serialized = serde_json::to_string(&metadata).expect("Failed to serialize metadata");
    let deserialized: StmFileMetadata =
        serde_json::from_str(&serialized).expect("Failed to deserialize metadata");

    assert_eq!(metadata, deserialized);
    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.filename, "photo.png");
    assert_eq!(deserialized.mime_type, "image/png");
    assert_eq!(deserialized.size, 2483921);
    assert_eq!(deserialized.file_object_number, 1);
}
