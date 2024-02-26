fn main() {
    unimplemented!()
}
// use anyhow::Result;
// use ed25519_dalek::SigningKey;
// use iroh_dns::{packet::NodeAnnounce, sig0::publish_doh_sig0};
// use iroh_net::key::SecretKey;
// use url::Url;
//
// #[tokio::main]
// async fn main() -> Result<()> {
//     tracing_subscriber::fmt::init();
//     let node_secret = SecretKey::generate();
//     let signing_key = SigningKey::from_bytes(&node_secret.to_bytes());
//     let node_id = node_secret.public();
//
//     println!("node_id {}", node_id);
//
//     let home_derp: Url = "https://derp.example".parse()?;
//     let msg = NodeAnnounce {
//         node_id,
//         home_derp: Some(home_derp.clone()),
//         home_dns: Default::default(),
//     };
//
//     // let name_server: SocketAddr = "127.0.0.1:5353".parse()?;
//     // let res = publish_dns_sig0(name_server, msg, signing_key).await;
//     let url: Url = "http://localhost:8080".parse()?;
//     let res = publish_doh_sig0(url, msg, signing_key).await;
//     println!("res {res:?}");
//     res
// }
