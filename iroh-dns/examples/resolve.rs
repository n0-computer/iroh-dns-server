use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use anyhow::Context;
use clap::Parser;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::{AsyncResolver, Name};
use iroh_dns::packet::{NodeAnnounce, IROH_NODE_TXT_NAME};
use iroh_net::NodeId;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
    #[clap(long)]
    ns: Option<String>,
}

#[derive(Debug, Parser)]
enum Command {
    Node {
        node_id: NodeId,
        #[clap(short, long, default_value = "iroh.")]
        origin: String,
    },
    Domain {
        domain: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let domain = match args.command {
        Command::Domain { domain } => format!("{}.{}", IROH_NODE_TXT_NAME, domain),
        Command::Node { node_id, origin } => {
            format!("{}.{}.{}", IROH_NODE_TXT_NAME, node_id, origin)
        }
    };

    let config = match args.ns {
        None => ResolverConfig::cloudflare(),
        Some(name) => {
            let addr = match name.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(_) => {
                    // todo: use hickory resolver here as well?
                    name.to_socket_addrs()?
                        .next()
                        .context("failed to resolve {name} to an IP address")?
                }
            };
            let mut config = ResolverConfig::new();
            let ns = NameServerConfig::new(addr, Protocol::Udp);
            config.add_name_server(ns);
            config
        }
    };

    println!("lookup: {domain}");
    let domain = Name::parse(&domain, Some(&Name::root()))?;

    let resolver = AsyncResolver::tokio(config, ResolverOpts::default());

    // Lookup the IP addresses associated with a name.
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    let response = resolver.txt_lookup(domain).await?;
    for txt in response.iter() {
        println!("{}", txt.to_string());
    }
    println!(
        "{:#?}",
        NodeAnnounce::from_hickory_lookup(response.as_lookup())
    );
    Ok(())
}
