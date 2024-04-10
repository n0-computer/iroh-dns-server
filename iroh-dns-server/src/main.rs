#![allow(unused_imports)]

use anyhow::Result;
use axum::{routing::get, Router};
use clap::Parser;
use futures::{Future, FutureExt};
use iroh_dns_server::{self as server, config::Config, dns::DnsHandler, state::AppState};
use iroh_metrics::metrics::start_metrics_server;
use server::metrics::init_metrics;
use server::run::run_with_config_until_ctrl_c;
use server::state::ZoneStore;
use server::store::SignedPacketStore;
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
    run_with_config_until_ctrl_c(config).await
}
