use std::io::Cursor;
use stm_stream::StreamReader;

#[test]
fn test_stream_reader_chunk_boundaries() {
    let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let cursor = Cursor::new(data);
    let mut reader = StreamReader::with_chunk_size(cursor, 8);

    let mut chunks = Vec::new();
    while let Some(chunk) = reader.read_next_chunk().unwrap() {
        chunks.push(chunk);
    }

    assert_eq!(chunks.len(), 5);
    assert_eq!(chunks[0], b"ABCDEFGH");
    assert_eq!(chunks[1], b"IJKLMNOP");
    assert_eq!(chunks[2], b"QRSTUVWX");
    assert_eq!(chunks[3], b"YZ012345");
    assert_eq!(chunks[4], b"6789");

    let flat: Vec<u8> = chunks.into_iter().flatten().collect();
    assert_eq!(&flat[..], data);
}
