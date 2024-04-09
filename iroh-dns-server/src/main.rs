#![allow(unused_imports)]

use anyhow::Result;
use axum::{routing::get, Router};
use clap::Parser;
use futures::{Future, FutureExt};
use iroh_dns_server::{self as server, config::Config, dns::DnsServer, state::AppState};
use iroh_metrics::metrics::start_metrics_server;
use server::metrics::init_metrics;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, error, error_span, Instrument, Span};

#[derive(Parser, Debug)]
struct Cli {
    /// Path to config file
    #[clap(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let config = if let Some(path) = args.config {
        Config::load(path).await?
    } else {
        Config::default()
    };

    init_metrics();

    let dns_server = DnsServer::new(&config.dns)?;
    let state = AppState {
        dns_server: dns_server.clone(),
    };

    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    tasks.spawn(with_span(
        error_span!("http"),
        server::http::serve(
            config.http.clone(),
            config.https.clone(),
            state,
            cancel.clone(),
        ),
    ));
    tasks.spawn(with_span(
        error_span!("dns"),
        server::dns::serve(config.dns.clone(), dns_server, cancel.clone()),
    ));

    if let Some(addr) = config.metrics_addr() {
        tasks.spawn(with_span(
            error_span!("metrics"),
            start_metrics_server(addr),
        ));
    }

    let mut final_res = Ok(());
    while let Some(next) = tasks.join_next().await {
        let (span, res) = next?;
        let _guard = span.enter();
        match res {
            Ok(()) => debug!("done"),
            Err(err) => {
                error!(?err, "failed");
                cancel.cancel();
                if final_res.is_ok() {
                    final_res = Err(err);
                }
            }
        }
    }
    final_res
}

fn with_span<F: Future>(span: Span, fut: F) -> impl Future<Output = (Span, F::Output)> {
    fut.instrument(span.clone()).map(|r| (span, r))
}
