use stm_file::file_type::detect_mime_type;

#[test]
fn test_png_detection() {
    let png_bytes = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
    assert_eq!(detect_mime_type(&png_bytes), "image/png");
}

#[test]
fn test_jpeg_detection() {
    let jpeg_bytes = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    assert_eq!(detect_mime_type(&jpeg_bytes), "image/jpeg");
}

#[test]
fn test_pdf_detection() {
    let pdf_bytes = b"%PDF-1.7 header content";
    assert_eq!(detect_mime_type(pdf_bytes), "application/pdf");
}

#[test]
fn test_zip_detection() {
    let zip_bytes = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
    assert_eq!(detect_mime_type(&zip_bytes), "application/zip");
}

#[test]
fn test_mp4_detection() {
    let mut mp4_bytes = vec![0x00, 0x00, 0x00, 0x18];
    mp4_bytes.extend_from_slice(b"ftypisom");
    assert_eq!(detect_mime_type(&mp4_bytes), "video/mp4");
}

#[test]
fn test_mp3_detection() {
    let mp3_id3 = b"ID3\x03\x00\x00\x00";
    assert_eq!(detect_mime_type(mp3_id3), "audio/mpeg");

    let mp3_sync = [0xFF, 0xFB, 0x90, 0x64];
    assert_eq!(detect_mime_type(&mp3_sync), "audio/mpeg");
}

#[test]
fn test_unknown_detection() {
    let unknown_bytes = b"random plain text or binary blob";
    assert_eq!(detect_mime_type(unknown_bytes), "application/octet-stream");
}
