use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::SigningKey;
use iroh_dns::{packet::NodeAnnounce, pkarr::publish_pkarr};
use iroh_net::key::SecretKey;
use url::Url;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(short, long, default_value = "http://localhost:8080/pkarr")]
    url: Url,
    #[clap(short, long, default_value = "https://myderper.io")]
    derp: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let node_secret = match std::env::var("IROH_SECRET") {
        Ok(secret) => SecretKey::from_str(&secret)?,
        Err(_) => {
            let node_secret = SecretKey::generate();
            println!("IROH_SECRET={node_secret}");
            node_secret
        }
    };
    let signing_key = SigningKey::from_bytes(&node_secret.to_bytes());
    let node_id = node_secret.public();

    println!("NODE_ID={}", node_id);

    let msg = NodeAnnounce {
        node_id,
        home_derp: Some(args.derp),
        home_dns: Default::default(),
    };

    publish_pkarr(args.url, msg, signing_key).await?;
    println!("published");
    Ok(())
}
