#![allow(unused_imports)]

use anyhow::Result;
use axum::{routing::get, Router};
use clap::Parser;
use magic_dns::config::Config;
use magic_dns::dns::DnsServer;
use magic_dns::state::AppState;
use tokio_util::sync::CancellationToken;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
struct Cli {
    // /// Domains
    // #[clap(short, required = true)]
    // domains: Vec<String>,
    //
    // /// Contact info
    // #[clap(short)]
    // email: Vec<String>,
    //
    // /// Cache directory
    // #[clap(short)]
    // cache: Option<PathBuf>,
    //
    // /// Use Let's Encrypt production environment
    // /// (see https://letsencrypt.org/docs/staging-environment/)
    // #[clap(long)]
    // prod: bool,
    //
    // #[clap(long, default_value = "8443")]
    // https_port: u16,
    //
    // #[clap(long, default_value = "8080")]
    // http_port: u16,
    //
    // #[clap(short, long)]
    // letsencrypt: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let _args = Cli::parse();
    let config = Config::default();
    let mut tasks = JoinSet::new();

    let cancel = CancellationToken::new();

    let dns_server = DnsServer::new(&config.dns, "server".to_string())?;
    let state = AppState {
        dns_server: dns_server.clone()
    };

    tasks.spawn(async move {
        magic_dns::http::serve(config.http, state).await
    });

    tasks.spawn(async move {
        magic_dns::dns::serve(&config.dns, dns_server, cancel).await
    });

    while let Some(res) = tasks.join_next().await {
        res??;
    }
    
    Ok(())
}

