use anyhow::{bail, Result};
use iroh_net::{key::SecretKey, AddrInfo};
use pkarr::PkarrClient;
use url::Url;

use crate::{packet::NodeAnnounce, resolve::Config};

pub async fn publish_pkarr(
    relay_url: Url,
    announce: NodeAnnounce,
    signing_key: ed25519_dalek::SigningKey,
) -> Result<()> {
    if &signing_key.verifying_key().to_bytes() != announce.node_id.as_bytes() {
        bail!("key mismatch: signing key does not match node id");
    }
    let signed_packet = announce.into_pkarr_signed_packet(signing_key)?;
    let client = PkarrClient::new();
    client.relay_put(&relay_url, &signed_packet).await?;
    Ok(())
}

#[derive(Debug)]
pub struct Publisher {
    pkarr_relay: Url,
    pkarr: PkarrClient,
    secret: SecretKey,
}

impl Publisher {
    pub fn new(config: &Config, secret: SecretKey) -> Self {
        let pkarr = PkarrClient::builder().build();
        Self {
            pkarr_relay: config.pkarr_url.clone(),
            pkarr,
            secret,
        }
    }

    pub async fn publish(&self, info: &AddrInfo) -> Result<()> {
        let an = NodeAnnounce {
            node_id: self.secret.public(),
            home_derp: info.derp_url.clone(),
            home_dns: Default::default(),
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.secret.to_bytes());
        let signed_packet = an.into_pkarr_signed_packet(signing_key)?;
        self.pkarr
            .relay_put(&self.pkarr_relay, &signed_packet)
            .await?;
        Ok(())
    }
}
