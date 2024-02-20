use anyhow::Result;
use axum::routing::post;
use axum::{routing::get, Router};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::task::JoinSet;
use tracing::info;

mod doh;
mod error;
mod tls;
mod publish;
mod extract;

use crate::state::AppState;

pub use self::tls::CertMode;

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub http_port: Option<u16>,
    pub https: Option<HttpsConfig>,
}

#[derive(Debug, Clone)]
pub struct HttpsConfig {
    pub port: u16,
    pub cert_mode: CertMode,
    pub cert_hostname: String,
}

pub async fn serve(config: HttpConfig, state: AppState) -> Result<()> {
    let app = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route("/publish", post(publish::post))
        .route("/", get(|| async { "Hello world!" }))
        .with_state(state);

    let mut tasks = JoinSet::new();

    // launch http
    if let Some(port) = config.http_port {
        let app = app.clone();
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        info!("HTTP server listening on {addr}");
        let fut =
            axum_server::bind(addr).serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tasks.spawn(fut);
    };

    // launch https
    if let Some(config) = config.https {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
        let cert_mode = tls::CertMode::SelfSigned;
        info!("HTTPS server listening on {addr}");
        let acceptor = {
            let cache_path = PathBuf::from("./cert-cache");
            cert_mode.build(&config.cert_hostname, cache_path).await?
        };
        let fut = axum_server::bind(addr)
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tasks.spawn(fut);
    }
    while let Some(_) = tasks.join_next().await {
        // nothing to do
    }
    Ok(())
}
