use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{io, net::Ipv4Addr, path::Path};

use crate::{
    dns::DnsConfig,
    http::{CertMode, HttpConfig, HttpsConfig},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub http: Option<HttpConfig>,
    pub https: Option<HttpsConfig>,
    pub dns: DnsConfig,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Config> {
        let s = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read {}", path.as_ref().to_string_lossy()))?;
        let config: Config = toml::from_str(&s)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: Some(HttpConfig { port: 8080 }),
            https: Some(HttpsConfig {
                port: 8443,
                domain: "localhost".to_string(),
                cert_mode: CertMode::SelfSigned,
                letsencrypt_contact: None,
                letsencrypt_prod: false,
            }),
            dns: DnsConfig {
                default_soa:
                    "dns1.irohdns.example hostmaster.irohdns.example 0 10800 3600 604800 3600"
                        .to_string(),
                origin: "irohdns.example.".to_string(),
                port: 5353,
                default_ttl: 900,
                additional_origins: vec!["iroh.".to_string()],
                ipv4_addr: Some(Ipv4Addr::LOCALHOST),
                ns_name: Some("ns1.irohdns.example.".to_string())
            },
        }
    }
}
