use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use axum::{
    extract::ConnectInfo,
    handler::Handler,
    http::{Method, Request},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tower_http::{
    cors::{self, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, span, Level};

mod doh;
mod error;
mod extract;
mod pkarr;
mod rate_limiting;
mod tls;

use crate::config::Config;
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
    if http_config.is_none() && https_config.is_none() {
        bail!("Either http or https config is required");
    }

    // configure cors middleware
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        // allow requests from any origin
        .allow_origin(cors::Any);

    // configure tracing middleware
    let trace = TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
        let conn_info = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .expect("connectinfo extension to be present");
        let span = span!(
        Level::DEBUG,
            "http_request",
            method = ?request.method(),
            uri = ?request.uri(),
            src = %conn_info.0,
            );
        span
    });

    // configure rate limiting middleware
    let rate_limit = rate_limiting::create();

    // configure routes
    //
    // only the pkarr::put route gets a rate limit
    let router = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/pkarr/:key",
            get(pkarr::get).put(pkarr::put.layer(rate_limit)),
        )
        .route("/healthcheck", get(|| async { "OK" }))
        .route("/", get(|| async { "Hi!" }))
        .with_state(state);

    // configure app
    let app = router.layer(cors).layer(trace);

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
        info!("HTTPS server listening on {addr}");
        let acceptor = {
            let cache_path = Config::data_dir()?
                .join("cert_cache")
                .join(config.cert_mode.to_string());
            tokio::fs::create_dir_all(&cache_path)
                .await
                .with_context(|| format!("failed to create cert cache dir at {cache_path:?}"))?;
            config
                .cert_mode
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
