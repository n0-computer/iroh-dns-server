use anyhow::Result;
use axum::routing::post;
use axum::{routing::get, Router};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::info;

mod doh;
mod pkarr;
mod publish;

mod error;
mod extract;
mod tls;

use crate::state::AppState;

pub use self::tls::CertMode;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpConfig {
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HttpsConfig {
    pub port: u16,
    pub domain: String,
    pub cert_mode: CertMode,
    pub letsencrypt_contact: Option<String>,
    pub letsencrypt_prod: bool,
}

pub async fn serve(
    http_config: Option<HttpConfig>,
    https_config: Option<HttpsConfig>,
    state: AppState,
    cancel: CancellationToken,
) -> Result<()> {
    let app = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route("/pkarr/:key", get(pkarr::get).put(pkarr::put))
        // .route("/publish", post(publish::post))
        .route("/", get(|| async { "Hello world!" }))
        .with_state(state);

    let mut tasks = JoinSet::new();

    // launch http
    if let Some(config) = http_config {
        let app = app.clone();
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
        info!("HTTP server listening on {addr}");
        let fut =
            axum_server::bind(addr).serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tasks.spawn(fut);
    };

    // launch https
    if let Some(config) = https_config {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.port));
        let cert_mode = tls::CertMode::SelfSigned;
        info!("HTTPS server listening on {addr}");
        let acceptor = {
            let cache_path = PathBuf::from("./cert-cache");
            cert_mode
                .build(
                    &config.domain,
                    cache_path,
                    config.letsencrypt_contact,
                    config.letsencrypt_prod,
                )
                .await?
        };
        let fut = axum_server::bind(addr)
            .acceptor(acceptor)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());
        tasks.spawn(fut);
    }

    loop {
        tokio::select! {
            // todo: graceful cancellation
            _ = cancel.cancelled() => tasks.abort_all(),
            res = tasks.join_next() => match res {
                None => break,
                Some(res) => res??,
            }
        }
    }

    Ok(())
}
