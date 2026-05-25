//! Federation HTTP daemon — public peer endpoints + loopback `/internal/`
//! endpoints used by the Flask admin panel and CLI for sign-and-send actions.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::signal;
use tracing::info;

mod handlers;
mod outbound;
mod poller;
mod state;

use tower_http::trace::TraceLayer;

pub use outbound::send_peer_request;
pub use state::AppState;

pub async fn run(state: AppState) -> Result<()> {
    let bind = state.config.federation_bind.clone();
    let app = handlers::router(Arc::new(state.clone()))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    info!(%bind, "federation daemon listening");

    let nonce_gc = tokio::spawn(nonce_gc_loop(state.clone()));
    let poller_handle = tokio::spawn(poller::run_loop(state.clone()));

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum serve")?;

    nonce_gc.abort();
    poller_handle.abort();
    Ok(())
}

async fn nonce_gc_loop(state: AppState) {
    use std::time::Duration;
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        match honey_protocol::nonce::gc_expired(&state.pool).await {
            Ok(0) => {}
            Ok(n) => info!(deleted = n, "nonce gc"),
            Err(e) => tracing::warn!(error = ?e, "nonce gc failed"),
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = signal::ctrl_c();
    #[cfg(unix)]
    let term = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    info!("shutdown signal received");
}
