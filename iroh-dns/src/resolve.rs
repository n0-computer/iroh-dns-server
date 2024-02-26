use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, Name,
};
use iroh_net::{AddrInfo, NodeAddr, NodeId};
use url::Url;

use crate::packet::{NodeAnnounce, IROH_NODE_TXT_NAME};

#[derive(Debug)]
pub struct Config {
    pub pkarr_url: Url,
    pub dns_server_addr: Option<SocketAddr>,
    pub dns_server_domain: String,
}

impl Config {
    pub fn with_irohdns(domain: String) -> Result<Self> {
        let pkarr_url: Url = format!("https://{domain}/pkarr").parse()?;
        Ok(Self {
            pkarr_url,
            dns_server_addr: None,
            dns_server_domain: domain,
        })
    }
}

#[derive(Debug)]
pub struct Resolver {
    default_origin: Name,
    dns_resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl Resolver {
    pub async fn new(config: &Config) -> Result<Self> {
        let default_origin = Name::parse(&config.dns_server_domain, Some(&Name::root()))?;
        let dns_addr = match config.dns_server_addr {
            Some(addr) => addr,
            None => {
                // todo: use hickory resolver here as well?
                // todo: async
                config
                    .dns_server_domain
                    .to_socket_addrs()?
                    .next()
                    .context("failed to resolve {name} to an IP address")?
            }
        };
        let mut config = ResolverConfig::new();
        let ns = NameServerConfig::new(dns_addr, Protocol::Udp);
        config.add_name_server(ns);
        let dns_resolver = AsyncResolver::tokio(config, ResolverOpts::default());
        Ok(Self {
            dns_resolver,
            default_origin,
        })
    }
    pub async fn resolve_domain(&self, domain: String) -> Result<NodeAddr> {
        let domain = Name::parse(&domain, Some(&Name::root()))?;
        let domain = Name::parse(IROH_NODE_TXT_NAME, Some(&domain))?;
        let lookup = self.dns_resolver.txt_lookup(domain).await?;
        let an = NodeAnnounce::from_hickory_lookup(lookup.as_lookup())?;
        Ok(an.into())
    }

    pub async fn resolve_node_id(&self, node_id: NodeId) -> Result<AddrInfo> {
        let domain = Name::parse(&node_id.to_string(), Some(&self.default_origin))?;
        self.resolve_domain(domain.to_string())
            .await
            .map(|addr| addr.info)
    }
}
