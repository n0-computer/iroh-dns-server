use anyhow::{bail, Result};
use pkarr::PkarrClient;
use url::Url;

use crate::packet::NodeAnnounce;

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
