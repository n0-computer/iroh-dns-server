use anyhow::Result;
use ed25519_dalek::SigningKey;
use iroh_net::{key::SecretKey, AddrInfo, NodeId};
use pkarr::PkarrClient;
use url::Url;

use crate::packet::NodeAnnounce;

pub const IROH_TEST_PKARR_RELAY: &'static str = "https://testdns.iroh.link/pkarr";
pub const LOCALHOST_PKARR_RELAY: &'static str = "http://localhost:8080";

/// Publisher config
pub struct Config {
    pub secret_key: SecretKey,
    pub pkarr_relay: Url,
}

impl Config {
    pub fn new(secret_key: SecretKey, pkarr_relay: Url) -> Self {
        Self {
            secret_key,
            pkarr_relay,
        }
    }

    pub fn with_iroh_test(secret_key: SecretKey) -> Self {
        let pkarr_relay: Url = IROH_TEST_PKARR_RELAY.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }

    pub fn localhost_dev(secret_key: SecretKey) -> Self {
        let pkarr_relay: Url = LOCALHOST_PKARR_RELAY.parse().expect("url is valid");
        Self::new(secret_key, pkarr_relay)
    }
}

/// Publish node announces to a pkarr relay.
#[derive(Debug)]
pub struct Publisher {
    node_id: NodeId,
    signing_key: SigningKey,
    pkarr_relay: Url,
    pkarr_client: PkarrClient,
}

impl Publisher {
    pub fn new(config: Config) -> Self {
        let pkarr_client = PkarrClient::builder().build();
        let node_id = config.secret_key.public();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&config.secret_key.to_bytes());
        Self {
            node_id,
            signing_key,
            pkarr_relay: config.pkarr_relay,
            pkarr_client,
        }
    }

    pub async fn publish_addr_info(&self, info: &AddrInfo) -> Result<()> {
        let an = NodeAnnounce::new(self.node_id, info.derp_url.clone(), Default::default());
        let signed_packet = an.into_pkarr_signed_packet(&self.signing_key)?;
        self.pkarr_client
            .relay_put(&self.pkarr_relay, &signed_packet)
            .await?;
        Ok(())
    }
}
