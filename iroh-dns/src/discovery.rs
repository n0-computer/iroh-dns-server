use std::sync::Arc;

use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use iroh_net::key::SecretKey;
use iroh_net::magicsock::Discovery;
use iroh_net::{AddrInfo, NodeId};
use tracing::warn;

use crate::pkarr::Publisher;
use crate::resolve::{Config, Resolver};

#[derive(Debug)]
pub struct DnsDiscovery {
    publisher: Option<Arc<Publisher>>,
    resolver: Resolver,
}

impl DnsDiscovery {
    pub async fn with_irohdns(domain: String, secret: Option<SecretKey>) -> Result<Self> {
        let config = Config::with_irohdns(domain)?;
        Self::new(config, secret).await
    }

    pub async fn new(config: Config, secret: Option<SecretKey>) -> Result<Self> {
        let publisher = secret.map(|s| Arc::new(Publisher::new(&config, s)));
        let resolver = Resolver::new(&config).await?;
        Ok(Self {
            publisher,
            resolver,
        })
    }
}

impl Discovery for DnsDiscovery {
    fn publish(&self, info: &AddrInfo) {
        let info = info.clone();
        if let Some(publisher) = self.publisher.clone() {
            tokio::task::spawn(async move {
                if let Err(err) = publisher.publish(&info).await {
                    warn!("failed to publish address update: {err:?}");
                }
            });
        }
    }

    fn resolve<'a>(&'a self, node_id: &'a NodeId) -> BoxFuture<'a, Result<AddrInfo>> {
        self.resolver.resolve_node_id(*node_id).boxed()
    }
}
