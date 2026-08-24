/// Detects the MIME type of a file based on its magic bytes / format signature.
pub fn detect_mime_type(bytes: &[u8]) -> &'static str {
    if bytes.len() >= 8 && bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return "image/png";
    }

    if bytes.len() >= 3 && bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "image/jpeg";
    }

    if bytes.len() >= 4 && bytes.starts_with(b"%PDF") {
        return "application/pdf";
    }

    if bytes.len() >= 4 && bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return "application/zip";
    }

    // MP4 check: ftyp box typically at bytes 4..8
    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        return "video/mp4";
    }

    // MP3 check: ID3 tag or MPEG sync word (0xFF followed by 0xFB, 0xF3, 0xF2, or 0xE0 mask)
    if bytes.len() >= 3 && bytes.starts_with(b"ID3") {
        return "audio/mpeg";
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0 {
        return "audio/mpeg";
    }

    "application/octet-stream"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_detection() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        assert_eq!(detect_mime_type(&png), "image/png");
    }

    #[test]
    fn test_jpeg_detection() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_mime_type(&jpeg), "image/jpeg");
    }

    #[test]
    fn test_pdf_detection() {
        let pdf = b"%PDF-1.7 header content";
        assert_eq!(detect_mime_type(pdf), "application/pdf");
    }

    #[test]
    fn test_zip_detection() {
        let zip = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        assert_eq!(detect_mime_type(&zip), "application/zip");
    }

    #[test]
    fn test_mp4_detection() {
        let mut mp4 = vec![0x00, 0x00, 0x00, 0x18];
        mp4.extend_from_slice(b"ftypisom");
        assert_eq!(detect_mime_type(&mp4), "video/mp4");
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
        let unknown = b"Hello world, plain text without header";
        assert_eq!(detect_mime_type(unknown), "application/octet-stream");
    }
}
