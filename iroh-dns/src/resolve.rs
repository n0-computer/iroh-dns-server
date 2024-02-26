use std::{net::Ipv4Addr, str::FromStr};

use anyhow::Result;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, Name,
};
use iroh_net::{AddrInfo, NodeAddr, NodeId};

use crate::packet::{NodeAnnounce, IROH_NODE_TXT_NAME};

pub const IROH_TEST_DNS_IPV4: Ipv4Addr = Ipv4Addr::new(5, 75, 181, 3);
pub const IROH_TEST_DOMAIN: &'static str = "testdns.iroh.link.";
pub const EXAMPLE_DOMAIN: &'static str = "irohdns.example.";

/// Resolver config
pub struct Config {
    name_servers: NameServerConfigGroup,
    default_node_origin: String,
}

impl Config {
    // TODO: Add with_system_and_iroh_test()

    pub fn with_cloudflare_and_iroh_test() -> Self {
        let cloudflare_dns = NameServerConfigGroup::cloudflare();
        let cloudflare_https = NameServerConfigGroup::cloudflare_https();
        let iroh_test_https = NameServerConfigGroup::from_ips_https(
            &[IROH_TEST_DNS_IPV4.into()],
            443,
            IROH_TEST_DOMAIN.to_string(),
            true,
        );
        let iroh_test_dns =
            NameServerConfigGroup::from_ips_clear(&[IROH_TEST_DNS_IPV4.into()], 53, false);

        let mut name_servers = NameServerConfigGroup::new();
        name_servers.merge(cloudflare_https);
        name_servers.merge(cloudflare_dns);
        name_servers.merge(iroh_test_https);
        name_servers.merge(iroh_test_dns);
        Self {
            name_servers,
            default_node_origin: IROH_TEST_DOMAIN.to_string(),
        }
    }

    pub fn localhost_dev() -> Self {
        let name_servers =
            NameServerConfigGroup::from_ips_clear(&[Ipv4Addr::LOCALHOST.into()], 5353, true);
        Self {
            name_servers,
            default_node_origin: EXAMPLE_DOMAIN.to_string(),
        }
    }
}

/// Resolve iroh nodes through DNS
#[derive(Debug, Clone)]
pub struct Resolver {
    default_node_origin: Name,
    dns_resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl Resolver {
    pub fn new(config: Config) -> Result<Self> {
        let default_node_origin = Name::from_str(&config.default_node_origin)?;
        // TODO: If we add our default node origin as search domain, we can resolve just node IDs!
        // let domain = Some(config.default_node_origin);
        let domain = None;
        let resolv_conf = ResolverConfig::from_parts(domain, vec![], config.name_servers);
        let dns_resolver = AsyncResolver::tokio(resolv_conf, ResolverOpts::default());
        Ok(Self {
            dns_resolver,
            default_node_origin,
        })
    }
    pub async fn resolve_node_by_domain(&self, domain: &str) -> Result<NodeAddr> {
        let name = Name::from_str(&domain)?;
        self.resolve_node(&name).await
    }

    pub async fn resolve_node_by_id(&self, node_id: NodeId) -> Result<AddrInfo> {
        let name = Name::parse(&node_id.to_string(), Some(&self.default_node_origin))?;
        let addr = self.resolve_node(&name).await?;
        Ok(addr.info)
    }

    async fn resolve_node(&self, name: &Name) -> Result<NodeAddr> {
        let name = Name::parse(IROH_NODE_TXT_NAME, Some(name))?;
        let lookup = self.dns_resolver.txt_lookup(name).await?;
        let an = NodeAnnounce::from_hickory_lookup(lookup.as_lookup())?;
        Ok(an.into())
    }
}
