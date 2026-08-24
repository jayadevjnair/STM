use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use stm_manifest::StmManifest;

use crate::{error::ServerError, state::AppState};

pub async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path(manifest_id): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    if manifest_id.len() != 64 || hex::decode(&manifest_id).is_err() {
        return Err(ServerError::BadRequest("Invalid manifest ID".to_string()));
    }

    let manifest_path = state.manifests_dir.join(format!("{}.json", manifest_id));
    if !manifest_path.exists() {
        return Err(ServerError::NotFound("Manifest not found".to_string()));
    }

    let manifest_str = std::fs::read_to_string(&manifest_path).map_err(|e| {
        ServerError::Internal(format!("Failed to read manifest: {:?}", e))
    })?;

    let manifest: StmManifest = serde_json::from_str(&manifest_str).map_err(|e| {
        ServerError::Internal(format!("Failed to parse stored manifest: {:?}", e))
    })?;

    Ok((StatusCode::OK, Json(manifest)))
}

pub async fn post_manifest(
    State(state): State<Arc<AppState>>,
    Json(manifest): Json<StmManifest>,
) -> Result<impl IntoResponse, ServerError> {
    // 1. Parse manifest (done by Json extractor)
    // 2. Validate structure
    if manifest.chunks.len() as u64 != manifest.total_chunks {
        return Err(ServerError::BadRequest("Chunk count mismatch".to_string()));
    }

    // 3. Recalculate canonical content hash
    let computed_content_hash = manifest.content_hash();
    let computed_manifest_id = hex::encode(computed_content_hash);

    // 4. Verify manifest_id
    if manifest.manifest_id != computed_manifest_id {
        return Err(ServerError::BadRequest(
            "Manifest ID does not match computed content hash".to_string(),
        ));
    }

    // 5. & 6. Verify Ed25519 signature if signed, else reject unsigned
    if manifest.signature.is_none() || manifest.public_key.is_none() {
        return Err(ServerError::BadRequest(
            "Remote server requires signed manifests".to_string(),
        ));
    }

    manifest.verify_signature().map_err(|_| {
        ServerError::BadRequest("Invalid manifest signature".to_string())
    })?;

    // 7. Store using manifest_id
    let manifest_path = state
        .manifests_dir
        .join(format!("{}.json", manifest.manifest_id));

    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
        ServerError::Internal(format!("Failed to serialize manifest: {:?}", e))
    })?;

    std::fs::write(&manifest_path, manifest_json).map_err(|e| {
        ServerError::Internal(format!("Failed to save manifest: {:?}", e))
    })?;

    Ok(StatusCode::CREATED)
}
