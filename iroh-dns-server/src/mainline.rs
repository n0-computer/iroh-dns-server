// use std::{sync::Arc, time::Duration};
//
// use anyhow::Result;
// use iroh_net::NodeId;
// use pkarr::{PkarrClient, SignedPacket};
// use tracing::debug;
// use ttl_cache::TtlCache;
//
// const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
//
// struct MainlineResolver {
//     cache: TtlCache<NodeId, Arc<SignedPacket>>,
//     pkarr_client: PkarrClient,
// }
//
// impl MainlineResolver {
//     pub fn new(cache_capacity: usize) {
//         1
//     }
//
//     async fn resolve(&mut self, node_id: NodeId) -> Result<Option<Arc<SignedPacket>>> {
//         if let Some(packet) = self.cache.get(&node_id) {
//             return Ok(Some(Arc::clone(packet)));
//         }
//         let packet = self.resolve_dht(node_id).await?;
//         match packet {
//             Some(packet) => {
//                 self.cache
//                     .insert(node_id, Arc::new(packet), DEFAULT_CACHE_TTL);
//                 Ok(self.cache.get(&node_id).map(|x| Arc::clone(x)))
//             }
//             None => Ok(None),
//         }
//     }
//
//     async fn resolve_dht(&self, node_id: NodeId) -> Result<Option<SignedPacket>> {
//         let public_key = pkarr::PublicKey::try_from(*node_id.as_bytes())?;
//         debug!(node_id = %node_id.fmt_short(), public_key = %public_key.to_z32(), "mainline: resolve");
//         match self.pkarr_client.resolve(public_key).await {
//             Some(signed_packet) => {
//                 debug!(node_id = %node_id.fmt_short(), ts = %signed_packet.timestamp(), "mainline: found record");
//                 Ok(Some(signed_packet))
//             }
//             None => {
//                 debug!(node_id = %node_id.fmt_short(), "mainline: found nothing");
//                 Ok(None)
//             }
//         }
//     }
// }
// #[cfg(feature = "mainline-dht")]
// {
//     let Some(node_id_parsed) = node_id.parse().ok() else {
//         return Ok(None)
//     };
//     let res = self.resolve_node_record_from_mainline(node_id_parsed).await;
//     match res {
//         Ok(true) => {
//             info!(node_id = %node_id_parsed.fmt_short(), "mainline DHT: lookup success");
//             self.get_record_for_node(node_id, origin)
//         }
//         Ok(false) => {
//             info!(node_id = %node_id_parsed.fmt_short(), "mainline DHT: lookup empty");
//             Ok(None)
//         }
//         Err(err) => {
//             warn!(node_id = %node_id_parsed.fmt_short(), ?err, "mainline DHT: lookup failed");
//             Ok(None)
//         }
//     }
// }
//
// #[cfg(not(feature = "mainline-dht"))]
// #[cfg(feature = "mainline-dht")]
// pub async fn resolve_node_record_from_mainline(&self, node_id: NodeId) -> Result<bool> {
//     let public_key = pkarr::PublicKey::try_from(*node_id.as_bytes())?;
//     debug!(node_id = %node_id.fmt_short(), public_key = %public_key.to_z32(), "mainline: resolve");
//     match self.pkarr_client.resolve(public_key).await {
//         Some(signed_packet) => {
//             debug!(node_id = %node_id.fmt_short(), ts = %signed_packet.timestamp(), "mainline: found record");
//             self.upsert_pkarr(signed_packet, PacketSource::Mainline)?;
//             Ok(true)
//         }
//         None => {
//             debug!(node_id = %node_id.fmt_short(), "mainline: found nothing");
//             Ok(false)
//         }
//     }
// }
