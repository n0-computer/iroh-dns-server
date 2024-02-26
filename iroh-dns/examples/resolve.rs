use clap::Parser;
use clap::ValueEnum;
use iroh_dns::resolve::{Config, Resolver};
use iroh_net::NodeId;

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Env {
    /// Use cloudflare and the irohdns test server at testdns.iroh.link
    #[default]
    IrohTest,
    /// Use a localhost domain server listening on port 5353
    LocalDev,
}

#[derive(Debug, Parser)]
struct Cli {
    env: Env,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Node { node_id: NodeId },
    Domain { domain: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let config = match args.env {
        Env::IrohTest => Config::with_cloudflare_and_iroh_test(),
        Env::LocalDev => Config::localhost_dev(),
    };
    let resolver = Resolver::new(config)?;
    match args.command {
        Command::Node { node_id } => {
            let res = resolver.resolve_node_by_id(node_id).await?;
            println!("{res:#?}");
        }
        Command::Domain { domain } => {
            let res = resolver.resolve_node_by_domain(&domain).await?;
            println!("{res:#?}");
        }
    }
    Ok(())
}
