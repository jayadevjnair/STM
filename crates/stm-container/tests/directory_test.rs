use stm_container::{Directory, DirectoryEntry};
use stm_core::{ObjectFlags, StmError};

#[test]
fn valid_directory_passes() {
    let mut directory = Directory::new();

    directory.add(DirectoryEntry {
        oid: [1u8; 16],
        obj_type: 1,
        offset: 100,
        length: 50,
        flags: ObjectFlags::NONE,
    });

    directory.add(DirectoryEntry {
        oid: [2u8; 16],
        obj_type: 1,
        offset: 150,
        length: 50,
        flags: ObjectFlags::NONE,
    });

    assert!(directory.validate(500).is_ok());
}

#[test]
fn unordered_directory_fails() {
    let mut directory = Directory::new();

    directory.add(DirectoryEntry {
        oid: [2u8; 16],
        obj_type: 1,
        offset: 100,
        length: 50,
        flags: ObjectFlags::NONE,
    });

    directory.add(DirectoryEntry {
        oid: [1u8; 16],
        obj_type: 1,
        offset: 150,
        length: 50,
        flags: ObjectFlags::NONE,
    });

    assert!(matches!(
        directory.validate(500),
        Err(StmError::DirectoryOutOfOrder)
    ));
}

#[test]
fn object_outside_container_fails() {
    let mut directory = Directory::new();

    directory.add(DirectoryEntry {
        oid: [1u8; 16],
        obj_type: 1,
        offset: 450,
        length: 100,
        flags: ObjectFlags::NONE,
    });

    assert!(matches!(
        directory.validate(500),
        Err(StmError::ObjectOutOfBounds)
    ));
}

#[test]
fn binary_search_finds_object() {
    let mut directory = Directory::new();

    directory.add(DirectoryEntry {
        oid: [2u8; 16],
        obj_type: 1,
        offset: 100,
        length: 20,
        flags: ObjectFlags::NONE,
    });

    directory.add(DirectoryEntry {
        oid: [1u8; 16],
        obj_type: 1,
        offset: 120,
        length: 20,
        flags: ObjectFlags::NONE,
    });

    directory.sort_by_oid();

    let result = directory.find(&[2u8; 16]);

    assert!(result.is_some());
}
