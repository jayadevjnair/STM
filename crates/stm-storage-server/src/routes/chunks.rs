use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use stm_crypto::hash_bytes;
use stm_storage::ChunkStore;

use crate::{error::ServerError, state::AppState, validation::validate_hash_param};

pub async fn head_chunk(
    State(state): State<Arc<AppState>>,
    Path(hash_str): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let hash = validate_hash_param(&hash_str)?;

    let exists = state.chunk_store.has_chunk(&hash).map_err(|e| {
        ServerError::Internal(format!("Failed to check chunk existence: {:?}", e))
    })?;

    if exists {
        Ok(StatusCode::OK)
    } else {
        Err(ServerError::NotFound("Chunk not found".to_string()))
    }
}

pub async fn get_chunk(
    State(state): State<Arc<AppState>>,
    Path(hash_str): Path<String>,
) -> Result<impl IntoResponse, ServerError> {
    let hash = validate_hash_param(&hash_str)?;

    let data = state.chunk_store.get_chunk(&hash).map_err(|_| {
        ServerError::NotFound("Chunk not found".to_string())
    })?;

    Ok((StatusCode::OK, data))
}

pub async fn post_chunk(
    State(state): State<Arc<AppState>>,
    Path(hash_str): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    let hash = validate_hash_param(&hash_str)?;

    if body.len() > state.config.max_chunk_size {
        return Err(ServerError::BadRequest(format!(
            "Payload too large. Max size is {} bytes",
            state.config.max_chunk_size
        )));
    }

    let computed_hash = hash_bytes(&body);
    if computed_hash != hash {
        return Err(ServerError::BadRequest(
            "Computed hash of payload does not match the provided URL hash".to_string(),
        ));
    }

    // Check if it already exists (deduplication at server level)
    let exists = state.chunk_store.has_chunk(&hash).map_err(|e| {
        ServerError::Internal(format!("Failed to check chunk existence: {:?}", e))
    })?;

    if exists {
        return Ok(StatusCode::OK);
    }

    state.chunk_store.put_chunk(&hash, &body).map_err(|e| {
        ServerError::Internal(format!("Failed to store chunk: {:?}", e))
    })?;

    Ok(StatusCode::CREATED)
}
