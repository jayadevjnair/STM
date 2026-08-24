use axum::{
    routing::{get, head, post},
    Router,
};
use std::sync::Arc;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use crate::{
    routes::{chunks, health, manifests},
    state::AppState,
};

pub fn create_router(state: Arc<AppState>) -> Router {
    let max_chunk_size = state.config.max_chunk_size;

    Router::new()
        .route("/api/v1/health", get(health::health_check))
        .route("/api/v1/chunks/:hash", head(chunks::head_chunk))
        .route("/api/v1/chunks/:hash", get(chunks::get_chunk))
        .route(
            "/api/v1/chunks/:hash",
            post(chunks::post_chunk)
                .layer(RequestBodyLimitLayer::new(max_chunk_size)),
        )
        .route("/api/v1/manifests", post(manifests::post_manifest))
        .route(
            "/api/v1/manifests/:manifest_id",
            get(manifests::get_manifest),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
