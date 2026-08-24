use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::Serialize;
use std::{net::SocketAddr, path::PathBuf};
use tower_http::services::ServeDir;

use stm_parser::{ParserMode, StmParser};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .nest_service("/", ServeDir::new("crates/stm-server/static"))
        .route("/api/convert", post(handle_convert))
        .route("/api/verify", post(handle_verify))
        .route("/api/list", post(handle_list))
        .route("/api/extract", post(handle_extract))
        .route("/api/open", post(handle_open))
        .route("/api/preview", post(handle_preview))
        .route("/api/inspect", post(handle_inspect))
        .layer(DefaultBodyLimit::disable());

    let desired_port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let candidate_ports = if desired_port == 8080 {
        vec![8080, 8181, 3000, 8000]
    } else {
        vec![desired_port, 8080, 8181, 3000]
    };

    let mut listener = None;
    let mut bound_addr = None;

    for port in candidate_ports {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                bound_addr = Some(addr);
                listener = Some(l);
                break;
            }
            Err(e) => {
                if port == desired_port {
                    eprintln!("Notice: Could not bind to port {}: {}.", port, e);
                }
            }
        }
    }

    let listener = match listener {
        Some(l) => l,
        None => {
            eprintln!("Failed to bind to any candidate port.");
            return;
        }
    };

    let addr = bound_addr.unwrap();
    println!("STM Server running at:\n\nhttp://{}\n", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn handle_convert(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;
    let mut sign = false;
    let mut filename = String::from("file.bin");

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            if let Some(fname) = field.file_name() {
                filename = fname.to_string();
            }
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        } else if name == "sign" {
            if let Ok(data) = field.text().await {
                sign = data == "true";
            }
        }
    }

    let Some(payload) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let signing_key = if sign {
        let key_dir = PathBuf::from("keys");
        let key_path = key_dir.join("private.key");

        let sk = if key_path.exists() {
            let key_data = std::fs::read(&key_path).unwrap();
            stm_signature::load_signing_key(&key_data).unwrap()
        } else {
            std::fs::create_dir_all(&key_dir).unwrap();
            let sk = stm_signature::generate_signing_key();
            let private_key = sk.to_bytes();
            std::fs::write(&key_path, private_key).unwrap();
            println!("Generated new local key at {}", key_path.display());
            sk
        };
        Some(sk)
    } else {
        None
    };

    let stm_data = match stm_file::convert_bytes_to_stmf(&payload, &filename, signing_key.as_ref())
    {
        Ok(data) => data,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build container: {:?}", e),
            )
                .into_response()
        }
    };

    // Replace original extension with .stmf
    let out_filename = if let Some(idx) = filename.rfind('.') {
        format!("{}.stmf", &filename[..idx])
    } else {
        format!("{}.stmf", filename)
    };

    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", out_filename),
            ),
        ],
        stm_data,
    )
        .into_response()
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    merkle_valid: bool,
    signed: bool,
    signature_valid: Option<bool>,
    reason: Option<String>,
    total_length: u64,
    object_count: usize,
    merkle_root: String,
}

async fn handle_verify(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let parser = StmParser::new(ParserMode::Strict);
    match parser.parse_bytes(&data) {
        Ok(summary) => {
            let valid = summary.merkle_valid && summary.signature_valid.unwrap_or(true);
            let resp = VerifyResponse {
                valid,
                merkle_valid: summary.merkle_valid,
                signed: summary.signed,
                signature_valid: summary.signature_valid,
                reason: if !valid {
                    Some("Integrity checks failed".to_string())
                } else {
                    None
                },
                total_length: summary.total_length,
                object_count: summary.object_count,
                merkle_root: hex::encode(summary.merkle_root),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            let resp = VerifyResponse {
                valid: false,
                merkle_valid: false,
                signed: false,
                signature_valid: None,
                reason: Some(format!("{:?}", e)),
                total_length: 0,
                object_count: 0,
                merkle_root: String::new(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
    }
}

#[derive(Serialize)]
struct ListResponse {
    entries: Vec<EntryInfo>,
    error: Option<String>,
}

#[derive(Serialize)]
struct EntryInfo {
    oid: String,
    obj_type: u32,
    offset: u64,
    length: u64,
    flags: u32,
}

async fn handle_list(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let parser = StmParser::new(ParserMode::Strict);
    match parser.list_objects(&data) {
        Ok(entries) => {
            let mut info_entries = Vec::new();
            for e in entries {
                info_entries.push(EntryInfo {
                    oid: hex::encode(e.oid),
                    obj_type: e.obj_type,
                    offset: e.offset,
                    length: e.length,
                    flags: e.flags.0,
                });
            }
            (
                StatusCode::OK,
                Json(ListResponse {
                    entries: info_entries,
                    error: None,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::OK,
            Json(ListResponse {
                entries: vec![],
                error: Some(format!("{:?}", e)),
            }),
        )
            .into_response(),
    }
}

use stm_file::metadata::StmFileMetadata;

#[derive(Serialize)]
struct OpenResponse {
    valid: bool,
    merkle_valid: bool,
    signed: bool,
    signature_valid: Option<bool>,
    files: Vec<StmFileMetadata>,
    error: Option<String>,
}

#[derive(Serialize)]
struct InspectResponse {
    total_length: u64,
    object_count: usize,
    signed: bool,
    signature_valid: Option<bool>,
    merkle_valid: bool,
    merkle_root: String,
    metadata: Option<StmFileMetadata>,
    objects: Vec<EntryInfo>,
    error: Option<String>,
}

async fn handle_inspect(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let parser = StmParser::new(ParserMode::Strict);
    let summary = match parser.parse_bytes(&data) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::OK,
                Json(InspectResponse {
                    total_length: 0,
                    object_count: 0,
                    signed: false,
                    signature_valid: None,
                    merkle_valid: false,
                    merkle_root: String::new(),
                    metadata: None,
                    objects: vec![],
                    error: Some(format!("{:?}", e)),
                }),
            )
                .into_response();
        }
    };

    let entries = parser.list_objects(&data).unwrap_or_default();
    let mut info_entries = Vec::new();
    for e in entries {
        info_entries.push(EntryInfo {
            oid: hex::encode(e.oid),
            obj_type: e.obj_type,
            offset: e.offset,
            length: e.length,
            flags: e.flags.0,
        });
    }

    let oid_meta = [0u8; 16];
    let metadata: Option<StmFileMetadata> = parser
        .extract_object_by_oid(&data, &oid_meta)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());

    (
        StatusCode::OK,
        Json(InspectResponse {
            total_length: summary.total_length,
            object_count: summary.object_count,
            signed: summary.signed,
            signature_valid: summary.signature_valid,
            merkle_valid: summary.merkle_valid,
            merkle_root: hex::encode(summary.merkle_root),
            metadata,
            objects: info_entries,
            error: None,
        }),
    )
        .into_response()
}

async fn handle_open(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or("") == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let parser = StmParser::new(ParserMode::Strict);
    let summary = match parser.parse_bytes(&data) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::OK,
                Json(OpenResponse {
                    valid: false,
                    merkle_valid: false,
                    signed: false,
                    signature_valid: None,
                    files: vec![],
                    error: Some(format!("{:?}", e)),
                }),
            )
                .into_response();
        }
    };

    let mut files = vec![];
    let oid_meta = [0u8; 16]; // object 0
    if let Ok(meta_bytes) = parser.extract_object_by_oid(&data, &oid_meta) {
        if let Ok(metadata) = serde_json::from_slice::<StmFileMetadata>(&meta_bytes) {
            files.push(metadata);
        }
    }

    let valid = summary.merkle_valid && summary.signature_valid.unwrap_or(true);

    (
        StatusCode::OK,
        Json(OpenResponse {
            valid,
            merkle_valid: summary.merkle_valid,
            signed: summary.signed,
            signature_valid: summary.signature_valid,
            files,
            error: None,
        }),
    )
        .into_response()
}

async fn handle_preview(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;
    let mut object_number: Option<u64> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        } else if name == "object_number" {
            if let Ok(text) = field.text().await {
                object_number = text.parse().ok();
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };
    let obj_num = object_number.unwrap_or(1);

    let parser = StmParser::new(ParserMode::Strict);
    let summary = match parser.parse_bytes(&data) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid container: {:?}", e),
            )
                .into_response()
        }
    };

    if !summary.merkle_valid || !summary.signature_valid.unwrap_or(true) {
        return (StatusCode::FORBIDDEN, "Security validation failed").into_response();
    }

    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&obj_num.to_be_bytes());

    let file_data = match parser.extract_object_by_oid(&data, &oid_file) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Extract error: {:?}", e),
            )
                .into_response()
        }
    };

    let oid_meta = [0u8; 16];
    let mime_type = if let Ok(meta_bytes) = parser.extract_object_by_oid(&data, &oid_meta) {
        if let Ok(metadata) = serde_json::from_slice::<StmFileMetadata>(&meta_bytes) {
            if metadata.file_object_number == obj_num && !metadata.mime_type.is_empty() {
                metadata.mime_type
            } else {
                stm_file::file_type::detect_mime_type(&file_data).to_string()
            }
        } else {
            stm_file::file_type::detect_mime_type(&file_data).to_string()
        }
    } else {
        stm_file::file_type::detect_mime_type(&file_data).to_string()
    };

    ([(header::CONTENT_TYPE, mime_type)], file_data).into_response()
}

async fn handle_extract(mut multipart: Multipart) -> impl IntoResponse {
    let mut file_bytes = None;
    let mut object_number: Option<u64> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            if let Ok(data) = field.bytes().await {
                file_bytes = Some(data.to_vec());
            }
        } else if name == "object_number" {
            if let Ok(text) = field.text().await {
                object_number = text.parse().ok();
            }
        }
    }

    let Some(data) = file_bytes else {
        return (StatusCode::BAD_REQUEST, "No file uploaded").into_response();
    };

    let obj_num = object_number.unwrap_or(1);

    let parser = StmParser::new(ParserMode::Strict);
    let mut filename = String::from("extracted-file.bin");

    let oid_meta = [0u8; 16];
    if let Ok(meta_bytes) = parser.extract_object_by_oid(&data, &oid_meta) {
        if let Ok(metadata) = serde_json::from_slice::<StmFileMetadata>(&meta_bytes) {
            if metadata.file_object_number == obj_num {
                filename = metadata.filename;
            }
        }
    }

    let mut oid_file = [0u8; 16];
    oid_file[8..16].copy_from_slice(&obj_num.to_be_bytes());

    match parser.extract_object_by_oid(&data, &oid_file) {
        Ok(object_data) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{}\"", filename),
                ),
            ],
            object_data,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to extract: {:?}", e),
        )
            .into_response(),
    }
}
