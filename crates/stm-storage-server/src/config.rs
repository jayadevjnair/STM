pub struct ServerConfig {
    pub base_dir: String,
    pub max_chunk_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            base_dir: "stm-data".to_string(),
            // 4 MiB + 4 KiB tolerance
            max_chunk_size: (4 * 1024 * 1024) + 4096,
        }
    }
}
