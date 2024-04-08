use std::net::SocketAddr;

use clap::Parser;
use clap::ValueEnum;
use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::Protocol;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::AsyncResolver;
use iroh_net::discovery::dns::N0_TESTDNS_NODE_ORIGIN;
use iroh_net::dns::node_info::lookup_by_domain;
use iroh_net::dns::node_info::lookup_by_id;
use iroh_net::NodeId;

const LOCALHOST_DNS: &str = "127.0.0.1:5353";
const EXAMPLE_ORIGIN: &str = "irohdns.example";

#[derive(ValueEnum, Clone, Debug, Default)]
pub enum Env {
    /// Use cloudflare and the irohdns test server at testdns.iroh.link
    #[default]
    Default,
    /// Use a localhost domain server listening on port 5353
    Dev,
}

#[derive(Debug, Parser)]
struct Cli {
    #[clap(value_enum, short, long, default_value_t = Env::Default)]
    env: Env,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Resolve node info by node id.
    Node { node_id: NodeId },
    /// Resolve node info by domain.
    Domain { domain: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let (resolver, origin) = match args.env {
        Env::Default => (
            iroh_net::dns::default_resolver().clone(),
            N0_TESTDNS_NODE_ORIGIN,
        ),
        Env::Dev => {
            let nameserver: SocketAddr = LOCALHOST_DNS.parse()?;
            let mut config = ResolverConfig::new();
            let nameserver_config = NameServerConfig::new(nameserver, Protocol::Udp);
            config.add_name_server(nameserver_config);
            let resolver = AsyncResolver::tokio(config, Default::default());
            (resolver, EXAMPLE_ORIGIN)
        }
    };
    let node_addr = match args.command {
        Command::Node { node_id } => lookup_by_id(&resolver, &node_id, origin).await?,
        Command::Domain { domain } => lookup_by_domain(&resolver, &domain).await?,
    };
    let node_id = node_addr.node_id;
    let relay_url = node_addr
        .relay_url()
        .map(|u| u.to_string())
        .unwrap_or_default();
    println!("node_id:  {node_id}");
    println!("relay:    {relay_url}");
    Ok(())
}
