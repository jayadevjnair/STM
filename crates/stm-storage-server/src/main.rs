use std::sync::Arc;
use tokio::net::TcpListener;

use stm_storage_server::{
    config::ServerConfig,
    router::create_router,
    state::AppState,
};

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let config = ServerConfig::default();
    let state = AppState::new(config)?;
    let app_state = Arc::new(state);

    let app = create_router(app_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on 0.0.0.0:3000");

    axum::serve(listener, app).await?;
    
    Ok(())
}
