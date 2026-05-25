use honey_config::Config;
use honey_identity::Identity;
use sqlx::PgPool;
use std::sync::Arc;

/// Shared state for axum handlers + background tasks.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub identity: Arc<Identity>,
    pub pool: PgPool,
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(config: Config, identity: Identity, pool: PgPool) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("honey/{}", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("build http client");
        Self {
            config: Arc::new(config),
            identity: Arc::new(identity),
            pool,
            http,
        }
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }
}
