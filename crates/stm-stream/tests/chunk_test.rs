use std::io::Cursor;
use stm_stream::StreamReader;

#[test]
fn test_empty_stream_reader() {
    let cursor = Cursor::new(Vec::new());
    let mut reader = StreamReader::new(cursor);
    assert_eq!(reader.read_next_chunk().unwrap(), None);
}

#[test]
fn test_small_file_chunk() {
    let data = b"hello world".to_vec();
    let cursor = Cursor::new(data.clone());
    let mut reader = StreamReader::with_chunk_size(cursor, 1024);

    let chunk = reader.read_next_chunk().unwrap();
    assert_eq!(chunk, Some(data));
    assert_eq!(reader.read_next_chunk().unwrap(), None);
}

#[test]
fn test_exact_one_chunk() {
    let chunk_size = 64;
    let data = vec![42u8; chunk_size];
    let cursor = Cursor::new(data.clone());
    let mut reader = StreamReader::with_chunk_size(cursor, chunk_size);

    assert_eq!(reader.read_next_chunk().unwrap(), Some(data));
    assert_eq!(reader.read_next_chunk().unwrap(), None);
}

#[test]
fn test_exact_two_chunks() {
    let chunk_size = 64;
    let data = vec![7u8; chunk_size * 2];
    let cursor = Cursor::new(data.clone());
    let mut reader = StreamReader::with_chunk_size(cursor, chunk_size);

    let chunk1 = reader.read_next_chunk().unwrap().unwrap();
    let chunk2 = reader.read_next_chunk().unwrap().unwrap();

    assert_eq!(chunk1.len(), chunk_size);
    assert_eq!(chunk2.len(), chunk_size);
    assert_eq!(reader.read_next_chunk().unwrap(), None);
}

#[test]
fn test_non_divisible_chunks() {
    let chunk_size = 10;
    let data = vec![1u8; 25]; // 10, 10, 5
    let cursor = Cursor::new(data);
    let mut reader = StreamReader::with_chunk_size(cursor, chunk_size);

    let c1 = reader.read_next_chunk().unwrap().unwrap();
    let c2 = reader.read_next_chunk().unwrap().unwrap();
    let c3 = reader.read_next_chunk().unwrap().unwrap();

    assert_eq!(c1.len(), 10);
    assert_eq!(c2.len(), 10);
    assert_eq!(c3.len(), 5);
    assert_eq!(reader.read_next_chunk().unwrap(), None);
}
