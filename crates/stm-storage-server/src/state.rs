use std::path::PathBuf;
use std::sync::Arc;
use stm_storage::{ChunkStore, LocalChunkStore};

use crate::config::ServerConfig;

pub struct AppState {
    pub chunk_store: Arc<LocalChunkStore>,
    pub manifests_dir: PathBuf,
    pub config: ServerConfig,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Result<Self, std::io::Error> {
        let base_path = std::path::Path::new(&config.base_dir);
        let chunks_dir = base_path.join("chunks");
        let manifests_dir = base_path.join("manifests");

        std::fs::create_dir_all(&chunks_dir)?;
        std::fs::create_dir_all(&manifests_dir)?;

        let chunk_store = LocalChunkStore::new(&chunks_dir).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e))
        })?;

        Ok(Self {
            chunk_store: Arc::new(chunk_store),
            manifests_dir,
            config,
        })
    }
}
